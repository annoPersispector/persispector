"""Project-wide environment configuration."""

from __future__ import annotations

from pathlib import Path

from dotenv import find_dotenv, load_dotenv


def load_environment(dotenv_path: str | Path | None = None) -> Path | None:
    """Load a .env file without overriding variables already in the environment.

    When no path is supplied, search from the current working directory through
    its parents. This supports both installed CLI entry points and ``python -m``
    execution from a project directory.
    """

    if dotenv_path is None:
        discovered = find_dotenv(usecwd=True)
        if not discovered:
            return None
        resolved = Path(discovered).resolve()
    else:
        resolved = Path(dotenv_path).expanduser().resolve()
        if not resolved.is_file():
            return None

    load_dotenv(dotenv_path=resolved, override=False)
    return resolved
