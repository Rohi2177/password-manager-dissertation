# Password Manager — MSc Dissertation

**Rohith Halappa Chavan · University of Sheffield · MSc Cybersecurity and Artificial Intelligence · 2026**

This repository presents my dissertation, *Implementing a Password Manager: A Vault Broker Design for Limiting Credential Exposure After Unlock*. It includes the submitted Windows prototype, tests and evaluation evidence, together with the original dissertation report and submission archive.

I am continuing to work on the password manager project beyond the dissertation. The source code and results in this repository represent the **submitted academic snapshot**; they should not be assumed to include later changes.

## Dissertation and submission

- [Read the dissertation report (PDF)](dissertation/password-manager-dissertation.pdf)
- [Download the original project submission (ZIP)](dissertation/password-manager-submission.zip)
- [Read the original submission README](SUBMISSION_README.md)
- [View my cybersecurity portfolio](https://rohi2177.github.io/#work)

## Project overview

The project explores what happens when a password manager's interface is compromised after a vault has already been unlocked. I designed and built a Python-based Windows prototype that separates sensitive vault operations into a broker and uses short-lived, single-use approvals scoped to one action and one record. The documented vault protection includes Argon2id and AES-256-GCM; Windows Hello is used to authorise sensitive actions.

## Evaluation and limits

The submitted dissertation **reported** 305 passing automated tests and seven skipped. In a simplified Tamarin model, five security properties were verified and an executability result was recorded. These are historical results from the submission, not a claim that tests were rerun for this repository or that the complete application is secure. The model has boundaries, some Windows behaviour was mocked, and credentials may still be exposed after they are copied or revealed. See the report for details and remaining risks.

This is an academic prototype and source submission, not a finished installer or a security assurance for protecting real credentials.

## Repository contents

- `src/` — Python application, vault broker and security components
- `tests/` and `docs/` — automated tests and submitted test evidence
- `formal/` — Tamarin model and verification evidence
- `evaluation_evidence/` — submitted code-quality and dependency evidence
- `scripts/` — supporting scripts
- `dissertation/` — original report and original submission archive
- `SUBMISSION_README.md` — setup and use instructions from the submitted archive

## Running the submitted prototype

The submitted instructions specify Windows 11 build 22000 or later, 64-bit Python 3.12–3.14, and Windows Hello configured for the current account. From the repository root, the Python 3.14 example is:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
.\.venv\Scripts\python.exe -m password_manager
```

Use Python 3.12 or 3.13 in the first command if appropriate. The submission README contains usage, backup and test instructions; its tests use dummy accounts and temporary vaults, and some hardware-dependent behaviour needs separate verification on real Windows hardware.
