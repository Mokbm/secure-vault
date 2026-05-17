# SecureVault v2.0

SecureVault is a local command-line password manager written in Python. It creates an encrypted vault on your machine, generates secure passwords for accounts, copies passwords to the clipboard, and supports encrypted backup export/import.

## Features

- Create an encrypted local password vault
- Protect the vault with a master password
- Derive encryption keys with Argon2id
- Encrypt vault data with AES-256-GCM
- Generate random 20-character passwords
- Save passwords by account/service name
- Copy passwords to the clipboard
- Automatically clear copied passwords after 60 seconds
- Reset or delete saved account passwords
- Export encrypted backups
- Import encrypted backups
- Track failed login attempts with a timed lockout

## Security Design

SecureVault uses:

- Argon2id key derivation
  - 64 MB memory cost
  - 3 iterations
  - 4-way parallelism
- AES-256-GCM authenticated encryption
- AAD binding for vault metadata
- Atomic file writes for vault and state files
- A minimum 14-character master password
- A local denylist and simple checks for weak master passwords

## Important Limitations

- The lockout feature is only a convenience feature. A user with local filesystem access can bypass it by deleting or editing `security_state.json`.
- Secrets can exist in process memory while the program is running.
- A compromised machine, keylogger, malware, or hostile terminal session can steal secrets.
- Backups are encrypted, but this version does not include a full startup restore flow when the main vault file is missing.

## Requirements

- Python 3.10 or newer recommended
- Dependencies listed in `requirements.txt`

## Quick Start

Clone the repository:

```bash
git clone https://github.com/Mokbm/secure-vault.git
```

Open the project folder:

```bash
cd secure-vault
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment.

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
python secure_vault.py
```

On some Linux/macOS systems, use:

```bash
python3 secure_vault.py
```

## Usage

On first launch, SecureVault asks you to create and confirm a master password. After that, use the menu to add accounts, copy passwords, reset passwords, delete entries, and manage encrypted backups.

## Data Storage

SecureVault stores encrypted data outside the repository.

Windows:

```text
%APPDATA%\SecureVault\
```

macOS/Linux:

```text
~/.securevault/
```

Generated files:

```text
vault.json
security_state.json
backups/
```

## Project Structure

```text
.
|-- secure_vault.py
|-- requirements.txt
|-- README.md
|-- LICENSE
`-- .gitignore
```

## Dependencies

- `argon2-cffi` for Argon2id key derivation
- `cryptography` for AES-256-GCM encryption
- `pyperclip` for clipboard support

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
