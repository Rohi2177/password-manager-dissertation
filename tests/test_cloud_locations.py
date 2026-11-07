"""Cloud-location warnings are best-effort and never expose vault contents."""

from pathlib import Path

from password_manager.security.cloud_locations import cloud_sync_provider


def test_detects_path_inside_configured_onedrive(tmp_path: Path) -> None:

    root = tmp_path / "OneDrive"
    vault = root / "Desktop" / "fake.pmvault"

    assert cloud_sync_provider(vault, {"OneDrive": str(root)}) == "OneDrive"


def test_does_not_treat_sibling_prefix_as_inside_root(tmp_path: Path) -> None:

    root = tmp_path / "OneDrive"
    sibling = tmp_path / "OneDrive-Local" / "fake.pmvault"

    assert cloud_sync_provider(sibling, {"OneDrive": str(root)}) is None


def test_unknown_or_unconfigured_location_has_no_provider(tmp_path: Path) -> None:
    assert cloud_sync_provider(tmp_path / "local" / "fake.pmvault", {}) is None
