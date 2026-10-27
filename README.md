# VaultX Password Manager

A local, single-user password-manager learning project built with Python, Flask, SQLite and Fernet encryption.

## Features

- Master-password setup and unlock
- Add, search, reveal, copy, edit and delete saved accounts
- Generate random passwords
- Store encrypted credential values in a local SQLite database
- CSRF token checks on form submissions
- Responsive HTML/CSS interface rendered from `app.py`

## Requirements

- Python 3.10 or newer recommended
- pip

## Run locally

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser. The app is configured to bind to localhost only.

## Files created at runtime

The app creates these files beside `app.py`:

- `vault.db` — saved account records
- `vault.salt` — key-derivation salt
- `vault.hash` — master-password hash

These files are excluded from Git by `.gitignore`. Do not upload them, especially if they contain personal credentials.

## Important security note

This is an educational prototype, not a professionally audited password manager. Do not use it for real or high-risk passwords without a security review. In the current implementation, the derived `vault_key` is placed in Flask's client-side session cookie; this is a significant design weakness because Flask's default session is signed, not encrypted. A production-ready version should keep key material server-side and use hardened session/cookie settings before storing any real credentials.

## GitHub upload

1. Create a new repository on GitHub.
2. Extract this ZIP file.
3. Upload the project files (`app.py`, `requirements.txt`, `README.md`, `.gitignore`) to the repository.
4. Confirm that `vault.db`, `vault.salt`, `vault.hash`, `.env`, and `.venv` are not uploaded.

Do not publish real passwords, API keys, `.env` files, or your local vault data.
