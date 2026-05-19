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
from argon2 import low_level, exceptions as argon2_exceptions

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
    "weak_password": "Password is too weak or simple.",
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
    except (IOError, OSError):
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        return False
    except Exception:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        return False
    return True


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
    """Check if password meets strength requirements."""
    if not any(c.isupper() for c in password):
        return True
    if not any(c.islower() for c in password):
        return True
    if not any(c.isdigit() for c in password):
        return True
    if not any(c in string.punctuation for c in password):
        return True
    if len(set(password)) < 6:
        return True
    return False


def validate_master_password(password):
    """Validate master password meets requirements."""
    if len(password) < MIN_MASTER_PASSWORD:
        return False, f"Password must be at least {MIN_MASTER_PASSWORD} characters"
    if is_weak_password(password):
        return False, ERROR_MESSAGES["weak_password"]
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
    except Exception:
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
        except Exception:
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
            vault_data = json.load(f)
        required_keys = ["kdf", "nonce", "ciphertext", "verification"]
        if not all(k in vault_data for k in required_keys):
            return None
        return vault_data
    except Exception:
        return None


def save_vault_file(vault_data):
    """Save vault file with atomic write."""
    return atomic_write(VAULT_FILE, json.dumps(vault_data, indent=2))


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
    try:
        kdf_params = vault["kdf"]
        if "salt" not in kdf_params:
            return False
        salt = base64.b64decode(kdf_params["salt"])

        token_aad = serialize_aad({
            "type": "verification_token",
            "version": 2,
            "kdf": kdf_params.copy()
        })

        key = derive_key(master_password, salt, kdf_params)
        token_nonce = base64.b64decode(vault["verification"]["nonce"])
        token_ciphertext = base64.b64decode(vault["verification"]["ciphertext"])
        decrypted = decrypt_data(token_nonce, token_ciphertext, key, token_aad)
        return decrypted.decode() == VERIFICATION_TOKEN
    except (argon2_exceptions.HashingError, argon2_exceptions.VerifyMismatchError):
        return False
    except Exception:
        return False


def load_vault(master_password, vault_file):
    """Load and decrypt vault data."""
    if vault_file is None:
        return None

    try:
        kdf_params = vault_file["kdf"]
        if "salt" not in kdf_params:
            return None
        salt = base64.b64decode(kdf_params["salt"])

        vault_aad = serialize_aad({
            "version": 2,
            "kdf": kdf_params.copy(),
            "encryption": "AES-256-GCM"
        })

        key = derive_key(master_password, salt, kdf_params)
        nonce = base64.b64decode(vault_file["nonce"])
        ciphertext = base64.b64decode(vault_file["ciphertext"])
        decrypted = decrypt_data(nonce, ciphertext, key, vault_aad)
        vault_data = json.loads(decrypted)
        
        vault_file["data"] = vault_data
        vault_file["key"] = key
        return vault_file
    except (argon2_exceptions.HashingError, argon2_exceptions.VerifyMismatchError):
        print("Error: Could not decrypt vault. Check your master password.")
        return None
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

    if not save_vault_file(vault_to_save):
        return False

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
        except Exception:
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
    except Exception:
        print("Error: Invalid backup file")
        return

    if backup_data.get("format_version", 0) != 2:
        print("Error: Unsupported backup version")
        return

    if not all(k in backup_data for k in ["kdf", "nonce", "ciphertext"]):
        print("Error: Backup missing required fields")
        return

    backup_password = getpass.getpass("Enter backup's master password: ")

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
    decrypt_key = derive_key(backup_password, salt, kdf_params)

    backup_aad = serialize_aad({
        "version": 2,
        "kdf": kdf_params.copy(),
        "encryption": "AES-256-GCM"
    })

    try:
        nonce = base64.b64decode(backup_data["nonce"])
        ciphertext = base64.b64decode(backup_data["ciphertext"])
        decrypted = decrypt_data(nonce, ciphertext, decrypt_key, backup_aad)
        vault_data = json.loads(decrypted)
    except Exception:
        print("Error: Could not decrypt backup. Wrong password or corrupted data.")
        return

    vault["data"] = vault_data
    vault["kdf"] = kdf_params

    encrypt_key = derive_key(master_password, salt, kdf_params)

    token_aad = serialize_aad({
        "type": "verification_token",
        "version": 2,
        "kdf": kdf_params.copy()
    })
    token_nonce, token_ciphertext = encrypt_data(
        VERIFICATION_TOKEN.encode(), encrypt_key, token_aad
    )
    vault["verification"] = {
        "nonce": base64.b64encode(token_nonce).decode(),
        "ciphertext": base64.b64encode(token_ciphertext).decode()
    }

    if not save_vault(master_password, vault):
        print("Error: Failed to save vault after import. File may be locked or inaccessible.")
        return
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
        if not save_vault(password, vault):
            print("Error: Failed to save vault. File may be locked or inaccessible.")
            return
        print("Vault created successfully!")
        
    else:
        try:
            while True:
                if check_lockout():
                    return

                print("\n=== Login ===")
                password = getpass.getpass("Enter master password: ")

                if verify_master_password(password, vault_file):
                    break

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
        except KeyboardInterrupt:
            print("\nCancelled.")
            return
        except Exception as e:
            print(f"\nError: {e}")
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
                    input("Press Enter to continue...")
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
            if not save_vault(password, vault):
                print("Error: Failed to save vault. File may be locked or inaccessible.")
                continue
            print(f"Created: {name}")

            copy_to_clipboard(password_val)
            show = input("Show password? (y/n): ").lower()
            if show == 'y':
                print(f"Password: {password_val}")
                input("Press Enter to continue...")

        elif choice == "2" and accounts:
            name = input("Reset password for account (or b to go back): ").strip().lower()
            if name == 'b':
                continue
            if name in vault["data"]:
                confirm = input(f"Reset {name} password? (y/n): ").lower()
                if confirm == 'y':
                    vault["data"][name] = generate_secure_password()
                    if not save_vault(password, vault):
                        print("Error: Failed to save vault. File may be locked or inaccessible.")
                        continue
                    print(f"New password for {name}")

                    copy_to_clipboard(vault["data"][name])
                    show = input("Show password? (y/n): ").lower()
                    if show == 'y':
                        print(f"Password: {vault['data'][name]}")
                        input("Press Enter to continue...")
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
                    if not save_vault(password, vault):
                        print("Error: Failed to save vault. File may be locked or inaccessible.")
                        continue
                    print("Deleted")
            else:
                print("Account not found")

        elif choice == "4":
            export_backup(vault)
            input("\nPress Enter to continue...")

        elif choice == "5":
            import_backup(password, vault)
            vault = load_vault(password, load_vault_file())
            if vault is None:
                break
            input("\nPress Enter to continue...")

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
