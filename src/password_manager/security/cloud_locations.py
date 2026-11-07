"""Recognise configured cloud folders for storage warnings."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

_CLOUD_ROOTS = (
    ("OneDrive", "OneDrive"),
    ("OneDriveConsumer", "OneDrive"),
    ("OneDriveCommercial", "OneDrive for Business"),
    ("Dropbox", "Dropbox"),
    ("GoogleDrive", "Google Drive"),
    ("iCloudDrive", "iCloud Drive"),
)


def cloud_sync_provider(
    path: str | Path,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """An unrecognised location is not proof that the file stays on this computer."""

    environment = os.environ if environ is None else environ

    try:
        candidate = Path(path).expanduser().resolve(strict=False)

    except (OSError, RuntimeError, ValueError):
        return None

    for variable, provider in _CLOUD_ROOTS:
        configured = environment.get(variable)

        if not configured:
            continue
        try:
            root = Path(configured).expanduser().resolve(strict=False)

        except (OSError, RuntimeError, ValueError):
            continue

        if candidate == root or root in candidate.parents:
            return provider
    return None
