"""Copy an older vault using its known master passphrase. Never overwrite it."""

import argparse
import getpass
import sqlite3
from pathlib import Path

from password_manager.core.passphrases import PassphrasePolicyError
from password_manager.storage import VaultStorageError, convert_vault


def main() -> int:

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Existing vault to read")
    parser.add_argument("destination", type=Path, help="New vault file; must not already exist")

    args = parser.parse_args()

    passphrase = getpass.getpass("Current master passphrase: ")

    try:
        convert_vault(args.source, args.destination, passphrase)

    except (VaultStorageError, PassphrasePolicyError, OSError, sqlite3.Error) as error:
        print(f"Conversion failed: {error}")
        return 1

    finally:
        passphrase = ""

    print("Conversion complete. The new vault uses fresh keys and the same master passphrase.")
    print("The original file is unchanged. Open and check the new vault before using it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
