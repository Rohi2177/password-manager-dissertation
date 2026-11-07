"""Private-file hardening checks."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from password_manager.security.file_permissions import harden_private_file


def test_regular_file_is_hardened_without_changing_content(tmp_path: Path) -> None:

    path = tmp_path / "private-state.bin"
    path.write_bytes(b"fake non-secret test state")
    os.chmod(path, 0o666)  # noqa: S103 - deliberately permissive test fixture

    harden_private_file(path)

    assert path.read_bytes() == b"fake non-secret test state"
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_symbolic_link_is_rejected(tmp_path: Path) -> None:

    target = tmp_path / "target.bin"
    target.write_bytes(b"fake")
    link = tmp_path / "link.bin"

    try:
        link.symlink_to(target)

    except (NotImplementedError, OSError) as error:
        pytest.skip(f"This account cannot create symbolic links: {error}")

    try:
        harden_private_file(link)
    except OSError:
        pass

    else:
        raise AssertionError("Symbolic-link security state must be rejected.")
