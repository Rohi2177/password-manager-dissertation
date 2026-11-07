"""Keep the installed version consistent with the project metadata."""

import tomllib
from pathlib import Path

from password_manager import APP_VERSION


def test_package_version_matches_project() -> None:

    project = Path(__file__).resolve().parents[1] / "pyproject.toml"
    metadata = tomllib.loads(project.read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == APP_VERSION


def test_package_instructions_and_dependency_files_exist() -> None:

    root = Path(__file__).resolve().parents[1]
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert (root / metadata["project"]["readme"]).is_file()
    assert (root / "requirements-lock.txt").is_file()
    assert (root / "requirements-dev.txt").is_file()
