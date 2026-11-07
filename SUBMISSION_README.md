

# Password Manager

This is a Windows password manager written in Python. It stores account information in an encrypted vault and is offline-capable once the necessary packages are installed.

I split the application into two pieces. The main window is the one that the user sees. Another is the 'Vault Broker' which opens the vault , keeps the vault key while the vault is open , and services requests from the window . This helps to minimise password exposure if the main window is compromised.

This is just the source code and tests of the project. It is not a finished Windows installer.


## Requirements

* Windows 11, build 22000 or later
* 64-bit Python 3.12, 3.13 or 3.14
* Windows Hello configured for the current account


## Setup and run

Extract the ZIP file. Open PowerShell and run:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
.\.venv\Scripts\python.exe -m password_manager
```

If you have python 3.12 or 3.13 installed; use 3.12 or 3.13.
Installation may require internet but the application works offline.


## How to use it

1. Select **Create a new encrypted vault** and choose where you want to save it.

2. Type a master passphrase of at least 15 characters. It also has to pass the checks as shown by the application.

3. It is important to keep the master passphrase safe because it cannot be reset or recovered.

4. Set up an account, then verify the action using Windows Hello.

5. Save accounts to view, edit, copy, show or delete.

6. When finished, lock the vault.

Windows Hello authorises sensitive actions. It does not replace the master passphrase, and it does not store the vault key. If the Windows Hello check is cancelled or fails, then the action is denied.

By default the vault locks after five minutes of inactivity. You can change this in 'Settings'.
"Ctrl+Shift+L" emergency locks while the application is active.



## Vaults and backups

A backup is an encrypted copy of the vault. It uses the same master passphrase and cannot recover the forgotten passphrase.

Do not put vault files in the project folder or cloud-synced folders.
The application will warn you about some known cloud folders, but it can’t detect them all.


## Older vaults

Format-1 and format-3 vaults open as usual. To convert a format-2 vault:

```powershell
.\.venv\Scripts\python.exe scripts\convert_vault.py "E:\vaults\old.pmvault" "E:\vaults\converted.pmvault"
```

Change the example paths to the real ones. The destination should be a new file, so the old vault doesn’t get overwritten. This does not recover a lost master passphrase.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

The tests make use of dummy accounts and temporary vaults. They should not be run against a personal vault. Some Windows features rely on controlled test results, so the real Windows hardware still needs to be checked separately.
