r"""
SecureVault v2.0 - A secure command-line password manager

SECURITY DESIGN:
- Key Derivation: Argon2id (64 MB, 3 iterations, 4 threads) with metadata-stored params
- Encryption: AES-256-GCM (authenticated encryption) with AAD binding
- Master Password: Minimum 14 characters, validated against common passwords
- Storage: File-based in %APPDATA%\SecureVault\

SECURITY WARNINGS:
- This is a personal password manager. For high-value or enterprise accounts,
  use a professionally audited password manager with two-factor authentication.
- Lockout is a convenience feature only - does NOT protect against attackers
  with local filesystem access, who can delete security_state.json to bypass it.
- The real security comes from: strong master password + Argon2id + AES-256-GCM
"""

import os
import json
import time
import secrets
import string
import base64
import getpass
import threading
import tempfile
import platform
import pyperclip

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level

# ==============================================================================
# CONSTANTS
# ==============================================================================

# Platform-specific app data directory
if platform.system() == "Windows":
    APP_DATA = os.path.join(os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming"), "SecureVault")
else:
    APP_DATA = os.path.join(os.path.expanduser("~"), ".securevault")

VAULT_FILE = os.path.join(APP_DATA, "vault.json")
BACKUP_DIR = os.path.join(APP_DATA, "backups")
SECURITY_STATE_FILE = os.path.join(APP_DATA, "security_state.json")

# Argon2id parameters (OWASP-recommended)
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_TIME_COST = 3        # 3 iterations
ARGON2_PARALLELISM = 4      # 4 threads
ARGON2_SALT_LENGTH = 16     # 128-bit salt
ARGON2_KEY_LENGTH = 32      # 256-bit key for AES-256

# Other constants
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 60 * 60  # 1 hour
CLIPBOARD_CLEAR_TIME = 60   # 60 seconds
MIN_MASTER_PASSWORD = 14     # 14 characters
VERIFICATION_TOKEN = "SECURE_VAULT_V2"

# Error messages
ERROR_MESSAGES = {
    "decryption_failed": "Could not decrypt vault. Check your master password.",
    "corrupted": "Vault data appears corrupted.",
    "invalid_backup": "Backup file is invalid or unsupported version.",
    "import_failed": "Import failed. Current vault unchanged.",
    "wrong_password": "Incorrect master password.",
    "weak_password": "Password is too common or simple.",
}

# Common passwords denylist (top ~200 most common)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567890",
    "qwerty", "abc123", "password1", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "login", "passw0rd", "shadow",
    "sunshine", "princess", "football", "michael", "superman",
    "batman", "trustno1", "iloveyou", "hello", "charlie", "donald",
    "654321", "qwerty123", "access", "flower", "mustang", "internet",
    "starwars", "computer", "jesus", "maggie", "purple", "freedom",
    "whatever", "ginger", "hammer", "silver", "austin", "daniel",
    "rockyou", "amanda", "summer", "love", "ashley", "nicole",
    "bailey", "passw0rd123", "secret", "test", "testing", "babygirl",
    "chocolate", "cookie", "jordan", "alexandra", "secret123", "121212",
    "flower123", "password123", "password2", "qwertyuiop", "hunter2",
    "password12", "123123", "111111", "000000", "666666", "7777777",
    "88888888", "99999999", "password!", "p@ssw0rd", "p@ssword",
    "admin123", "root", "toor", "test1234", "test123", "changeme",
    "password01", "1234567", "123456a", "1q2w3e4r", "1q2w3e4r5t",
    "q1w2e3r4", "zxcvbnm", "asdfgh", "asdfghjkl", "qazwsxedc",
    "zaq12wsx", "zaq1xsw2", "xsw21qaz", "1qaz2wsx", "1qazxsw2",
    "password11", "password1234", "123456a1", "letmein123",
    "adminadmin", "rootroot", "administrator", "metallica",
    "samsung", "linkedin", "facebook", "twitter", "instagram",
    "myspace", "youtube", "gmail", "yahoo", "hotmail", "outlook",
    "password12345", "password123456", "trustno1", "letmein1",
    "dragon123", "monkey123", "master123", "baseball", "soccer",
    "hockey", "ranger", "rangers", "liverpool", "manutd", "chelsea",
    "arsenal", "yankees", "cowboys", "eagles", "patriots", "steelers",
    "lakers", "celtics", "miami", "boston", "chicago", "detroit",
    "jennifer", "joshua", "christina", "danielle", "jessica",
    "matthew", "andrew", "joseph", "ryan", "john", "robert",
    "william", "david", "richard", "thomas", "charles", "anthony",
    "steven", "paul", "mark", "donald", "steven", "peter",
    "password99", "secure", "secure123", "pass1234", "pass123",
    "qwerty1", "qwerty12", "qwerty1234", "asdf1234", "asdf123",
    "zxcv1234", "poiuytrewq", "mnbvcxz", "lkjhgfdsa", "1q2w3e",
    "1qaz2wsx3edc", "1qazxsw23edc", "1q2w3e4r5t6y7u8i9o0p"
}


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def ensure_directories():
    """Create app directories if they don't exist."""
    os.makedirs(APP_DATA, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)


def clear_screen():
    """Clear console screen between pages."""
    os.system('cls' if os.name == 'nt' else 'clear')


def serialize_aad(aad_dict):
    """Serialize AAD deterministically for encryption/decryption."""
    return json.dumps(aad_dict, sort_keys=True, separators=(",", ":")).encode()


def atomic_write(filepath, data):
    """Write data atomically using temp file + os.replace() with fsync."""
    dir_path = os.path.dirname(filepath)
    if not dir_path:
        dir_path = "."
    
    fd, temp_path = tempfile.mkstemp(dir=dir_path, prefix=".tmp_")
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, filepath)
    except:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def generate_secure_password(length=20):
    """Generate a cryptographically secure random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


# ==============================================================================
# CRYPTOGRAPHY
# ==============================================================================

def derive_key(master_password, salt, kdf_params):
    """Derive 32-byte key for AES-256-GCM using Argon2id."""
    return low_level.hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=kdf_params["time_cost"],
        memory_cost=kdf_params["memory_cost"],
        parallelism=kdf_params["parallelism"],
        hash_len=ARGON2_KEY_LENGTH,
        type=low_level.Type.ID
    )


def encrypt_data(plaintext, key, aad):
    """Encrypt data using AES-256-GCM with AAD."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_data(nonce, ciphertext, key, aad):
    """Decrypt data using AES-256-GCM with AAD."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ==============================================================================
# PASSWORD VALIDATION
# ==============================================================================

def is_weak_password(password):
    """Check if password is weak or commonly used."""
    if password.lower() in COMMON_PASSWORDS:
        return True
    if len(set(password)) < 4:
        return True
    if password.isdigit():
        return True
    if password.isalpha() and len(password) < 10:
        return True
    if len(set(password)) < len(password) // 2:
        return True
    return False


def validate_master_password(password):
    """Validate master password meets requirements."""
    if len(password) < MIN_MASTER_PASSWORD:
        return False, f"Password must be at least {MIN_MASTER_PASSWORD} characters"
    if is_weak_password(password):
        return False, "Password is too common or weak. Choose something more secure."
    return True, None


# ==============================================================================
# SECURITY STATE (LOCKOUT)
# ==============================================================================

def load_security_state():
    """Load security state (failed attempts, lockout)."""
    if not os.path.exists(SECURITY_STATE_FILE):
        return {"failed_attempts": 0, "lockout_until": None}
    
    try:
        with open(SECURITY_STATE_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"failed_attempts": 0, "lockout_until": None}


def save_security_state(state):
    """Save security state with atomic write."""
    atomic_write(SECURITY_STATE_FILE, json.dumps(state, indent=2))


def check_lockout():
    """Check if currently locked out."""
    state = load_security_state()
    lockout = state.get("lockout_until")
    if lockout:
        try:
            lockout_time = time.mktime(time.strptime(lockout, "%Y-%m-%dT%H:%M:%SZ"))
        except:
            save_security_state({"failed_attempts": 0, "lockout_until": None})
            return False
        
        remaining = lockout_time - time.time()
        if remaining > 0:
            mins = int(remaining // 60)
            print(f"\nToo many failed attempts. Locked out for {mins}m")
            print("\nNote: This lockout is a convenience feature only.")
            print("      It does NOT protect against:")
            print("      • Offline attacks with filesystem access")
            print("      • Deleting or modifying security_state.json")
            print("      • Credential extraction from vault.json")
            print("\n      Your security depends on the master password.")
            return True
        else:
            save_security_state({"failed_attempts": 0, "lockout_until": None})
    return False


def increment_attempts():
    """Increment failed attempts, apply lockout if needed."""
    state = load_security_state()
    state["failed_attempts"] += 1
    
    if state["failed_attempts"] >= MAX_ATTEMPTS:
        lockout_time = time.time() + LOCKOUT_DURATION
        state["lockout_until"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(lockout_time))
        print(f"\nToo many failed attempts. Locked out for {LOCKOUT_DURATION // 60} minutes")
        print("Note: Lockout can be bypassed by deleting security_state.json")
    
    save_security_state(state)
    return state["failed_attempts"]


def reset_lockout():
    """Reset failed attempts after successful login."""
    save_security_state({"failed_attempts": 0, "lockout_until": None})


# ==============================================================================
# VAULT OPERATIONS
# ==============================================================================

def load_vault_file():
    """Load vault file from disk."""
    if not os.path.exists(VAULT_FILE):
        return None
    try:
        with open(VAULT_FILE, 'r') as f:
            return json.load(f)
    except:
        return None


def save_vault_file(vault_data):
    """Save vault file with atomic write."""
    atomic_write(VAULT_FILE, json.dumps(vault_data, indent=2))


def create_vault(master_password):
    """Create a new vault with metadata."""
    salt = os.urandom(ARGON2_SALT_LENGTH)
    kdf_params = {
        "type": "argon2id",
        "memory_cost": ARGON2_MEMORY_COST,
        "time_cost": ARGON2_TIME_COST,
        "parallelism": ARGON2_PARALLELISM,
        "salt": base64.b64encode(salt).decode()
    }

    key = derive_key(master_password, salt, kdf_params)

    vault_aad = serialize_aad({
        "version": 2,
        "kdf": kdf_params.copy(),
        "encryption": "AES-256-GCM"
    })

    nonce, ciphertext = encrypt_data(json.dumps({}).encode(), key, vault_aad)

    token_aad = serialize_aad({
        "type": "verification_token",
        "version": 2,
        "kdf": kdf_params.copy()
    })
    token_nonce, token_ciphertext = encrypt_data(
        VERIFICATION_TOKEN.encode(), key, token_aad
    )

    vault = {
        "version": 2,
        "kdf": kdf_params,
        "encryption": {"type": "AES-256-GCM"},
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "verification": {
            "nonce": base64.b64encode(token_nonce).decode(),
            "ciphertext": base64.b64encode(token_ciphertext).decode()
        },
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    return vault


def verify_master_password(master_password, vault):
    """Verify master password against verification token."""
    kdf_params = vault["kdf"]
    salt = base64.b64decode(kdf_params["salt"])
    key = derive_key(master_password, salt, kdf_params)

    token_aad = serialize_aad({
        "type": "verification_token",
        "version": 2,
        "kdf": kdf_params.copy()
    })

    try:
        token_nonce = base64.b64decode(vault["verification"]["nonce"])
        token_ciphertext = base64.b64decode(vault["verification"]["ciphertext"])
        decrypted = decrypt_data(token_nonce, token_ciphertext, key, token_aad)
        return decrypted.decode() == VERIFICATION_TOKEN
    except:
        return False


def load_vault(master_password, vault_file):
    """Load and decrypt vault data."""
    if vault_file is None:
        return None

    kdf_params = vault_file["kdf"]
    salt = base64.b64decode(kdf_params["salt"])
    key = derive_key(master_password, salt, kdf_params)

    vault_aad = serialize_aad({
        "version": 2,
        "kdf": kdf_params.copy(),
        "encryption": "AES-256-GCM"
    })

    try:
        nonce = base64.b64decode(vault_file["nonce"])
        ciphertext = base64.b64decode(vault_file["ciphertext"])
        decrypted = decrypt_data(nonce, ciphertext, key, vault_aad)
        vault_data = json.loads(decrypted)
        
        vault_file["data"] = vault_data
        vault_file["key"] = key
        return vault_file
    except Exception:
        print("Error: Could not decrypt vault. Check your master password.")
        return None


def save_vault(master_password, vault):
    """Save vault with encryption."""
    kdf_params = vault["kdf"]
    salt = base64.b64decode(kdf_params["salt"])
    key = derive_key(master_password, salt, kdf_params)

    vault_aad = serialize_aad({
        "version": 2,
        "kdf": kdf_params.copy(),
        "encryption": "AES-256-GCM"
    })

    nonce, ciphertext = encrypt_data(
        json.dumps(vault["data"]).encode(), key, vault_aad
    )

    vault_to_save = {k: v for k, v in vault.items() if k not in ("key", "data")}
    vault_to_save["nonce"] = base64.b64encode(nonce).decode()
    vault_to_save["ciphertext"] = base64.b64encode(ciphertext).decode()
    vault_to_save["modified"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    save_vault_file(vault_to_save)

    vault["nonce"] = vault_to_save["nonce"]
    vault["ciphertext"] = vault_to_save["ciphertext"]
    vault["modified"] = vault_to_save["modified"]

    return True


# ==============================================================================
# CLIPBOARD
# ==============================================================================

def copy_to_clipboard(password):
    """Copy password to clipboard with auto-clear."""
    copied_password = password

    def clear_clipboard():
        time.sleep(CLIPBOARD_CLEAR_TIME)
        try:
            current = pyperclip.paste()
            if current == copied_password:
                pyperclip.copy("")
        except:
            pass

    try:
        pyperclip.copy(password)
        threading.Thread(target=clear_clipboard, daemon=True).start()
        print(f"Copied! Clipboard will clear in {CLIPBOARD_CLEAR_TIME} seconds")
        return True
    except Exception as e:
        print(f"Copy failed: {e}")
        return False


# ==============================================================================
# BACKUP & IMPORT
# ==============================================================================

def export_backup(vault):
    """Export vault to backup file."""
    existing = [f for f in os.listdir(BACKUP_DIR) if f.startswith('vault_') and f.endswith('.bak')]
    try:
        numbers = [int(f.split('_')[1].split('.')[0]) for f in existing]
        next_num = max(numbers) + 1
    except (ValueError, IndexError):
        next_num = 1

    backup_file = os.path.join(BACKUP_DIR, f"vault_{next_num:02d}.bak")

    backup_data = {
        "format_version": 2,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kdf": vault["kdf"].copy(),
        "nonce": vault["nonce"],
        "ciphertext": vault["ciphertext"]
    }

    atomic_write(backup_file, json.dumps(backup_data, indent=2))
    print(f"Backup saved to: {backup_file}")


def import_backup(master_password, vault):
    """Import vault from backup file."""
    backups = [f for f in os.listdir(BACKUP_DIR) if f.startswith('vault_') and f.endswith('.bak')]
    if not backups:
        print("No backups found")
        return

    print("\nAvailable backups:")
    for b in sorted(backups):
        print(f"  - {b}")

    filename = input("\nEnter backup filename (or b to go back): ").strip()
    if filename == 'b':
        return

    full_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(full_path):
        print("File not found")
        return

    try:
        with open(full_path, 'r') as f:
            backup_data = json.load(f)
    except:
        print("Error: Invalid backup file")
        return

    if backup_data.get("format_version", 0) != 2:
        print("Error: Unsupported backup version")
        return

    if not all(k in backup_data for k in ["kdf", "nonce", "ciphertext"]):
        print("Error: Backup missing required fields")
        return

    state = load_security_state()
    if state.get("failed_attempts", 0) >= MAX_ATTEMPTS:
        print("Too many failed attempts. Please wait for lockout to expire.")
        return

    safety_file = os.path.join(BACKUP_DIR, f"safety_pre_import_{int(time.time())}.bak")
    safety_data = {
        "format_version": 2,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kdf": vault["kdf"].copy(),
        "nonce": vault["nonce"],
        "ciphertext": vault["ciphertext"]
    }
    atomic_write(safety_file, json.dumps(safety_data, indent=2))
    print(f"Safety backup created: {safety_file}")

    kdf_params = backup_data["kdf"]
    salt = base64.b64decode(kdf_params["salt"])
    key = derive_key(master_password, salt, kdf_params)

    backup_aad = serialize_aad({
        "version": 2,
        "kdf": kdf_params.copy(),
        "encryption": "AES-256-GCM"
    })

    try:
        nonce = base64.b64decode(backup_data["nonce"])
        ciphertext = base64.b64decode(backup_data["ciphertext"])
        decrypted = decrypt_data(nonce, ciphertext, key, backup_aad)
        vault_data = json.loads(decrypted)
    except:
        print("Error: Could not decrypt backup. Wrong password or corrupted data.")
        return

    vault["data"] = vault_data
    vault["kdf"] = kdf_params

    token_aad = serialize_aad({
        "type": "verification_token",
        "version": 2,
        "kdf": kdf_params.copy()
    })
    token_nonce, token_ciphertext = encrypt_data(
        VERIFICATION_TOKEN.encode(), key, token_aad
    )
    vault["verification"] = {
        "nonce": base64.b64encode(token_nonce).decode(),
        "ciphertext": base64.b64encode(token_ciphertext).decode()
    }

    save_vault(master_password, vault)
    print(f"Imported {len(vault_data)} accounts")


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    ensure_directories()

    vault_file = load_vault_file()

    if vault_file is None:
        print("\n=== SecureVault v2.0 ===")
        print("\nNew vault setup:")

        password = getpass.getpass("Create master password: ")
        confirm = getpass.getpass("Confirm master password: ")

        if password != confirm:
            print("Passwords don't match")
            return

        valid, error = validate_master_password(password)
        if not valid:
            print(error)
            return

        vault = create_vault(password)
        vault["data"] = {}
        save_vault(password, vault)
        print("Vault created successfully!")
        
    else:
        if check_lockout():
            return

        print("\n=== Login ===")
        password = getpass.getpass("Enter master password: ")

        if not verify_master_password(password, vault_file):
            attempts = increment_attempts()
            remaining = MAX_ATTEMPTS - attempts
            if remaining > 0:
                print(f"Incorrect password. {remaining} attempts remaining")
            else:
                check_lockout()
            return

        reset_lockout()
        vault = load_vault(password, vault_file)

        if vault is None:
            print("Error: Could not load vault")
            return

    while True:
        clear_screen()
        print("\n=== Password Vault ===")
        accounts = list(vault["data"].keys())
        print("1) Add new account")
        if accounts:
            print("2) Reset password")
            print("3) Delete account")
        print("4) Export backup")
        print("5) Import backup")
        print("0) Exit")
        if accounts:
            print("--- Accounts ---")
            for i, acc in enumerate(accounts):
                letter = chr(ord('a') + i)
                print(f"{letter}) {acc}")

        choice = input("\nSelect: ").strip()

        if choice == "0":
            print("Goodbye!")
            break

        if accounts and choice.isalpha() and len(choice) == 1:
            idx = ord(choice.lower()) - ord('a')
            if 0 <= idx < len(accounts):
                name = accounts[idx]
                password_val = vault["data"][name]
                print(f"\n{name}: [Hidden]")

                copy_to_clipboard(password_val)
                show = input("Show password? (y/n): ").lower()
                if show == 'y':
                    print(f"Password: {password_val}")
                continue

        if choice == "1":
            name = input("Account name (e.g., Instagram, Gmail, X) or b to go back: ").strip().lower()
            if name == 'b':
                continue
            if name in vault["data"]:
                print("Account already exists!")
                continue

            password_val = generate_secure_password()
            vault["data"][name] = password_val
            save_vault(password, vault)
            print(f"Created: {name}")

            copy_to_clipboard(password_val)
            show = input("Show password? (y/n): ").lower()
            if show == 'y':
                print(f"Password: {password_val}")

        elif choice == "2" and accounts:
            name = input("Reset password for account (or b to go back): ").strip().lower()
            if name == 'b':
                continue
            if name in vault["data"]:
                confirm = input(f"Reset {name} password? (y/n): ").lower()
                if confirm == 'y':
                    vault["data"][name] = generate_secure_password()
                    save_vault(password, vault)
                    print(f"New password for {name}")

                    copy_to_clipboard(vault["data"][name])
                    show = input("Show password? (y/n): ").lower()
                    if show == 'y':
                        print(f"Password: {vault['data'][name]}")
            else:
                print("Account not found")

        elif choice == "3" and accounts:
            name = input("Delete account name (or b to go back): ").strip().lower()
            if name == 'b':
                continue
            if name in vault["data"]:
                confirm = input(f"Delete {name}? (y/n): ").lower()
                if confirm == 'y':
                    del vault["data"][name]
                    save_vault(password, vault)
                    print("Deleted")
            else:
                print("Account not found")

        elif choice == "4":
            export_backup(vault)

        elif choice == "5":
            import_backup(password, vault)
            vault = load_vault(password, load_vault_file())
            if vault is None:
                break

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()