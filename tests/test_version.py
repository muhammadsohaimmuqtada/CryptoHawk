import tomllib
from pathlib import Path

from cryptohawk import __version__


def test_runtime_version_matches_project_metadata() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert __version__ == pyproject["project"]["version"]
    assert __version__ == "0.9.0"
