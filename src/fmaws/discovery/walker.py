"""Bounded, symlink-safe enumeration of project files."""

import os
from pathlib import Path

from fmaws.errors import ConfigError

MAX_FILE_BYTES = 2_000_000
MAX_FILES = 5_000
SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", ".terraform", "__pycache__", "dist",
    "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode",
}  # fmt: skip


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (ValueError, OSError):
        return False
    return True


def walk(root: Path, paths: list[str], exclude: list[Path]) -> tuple[list[Path], list[str]]:
    """Sorted files under ``root`` (or the configured ``paths``) and notes on what was skipped."""
    root = root.resolve()
    excluded = {p.resolve() for p in exclude}
    starts: list[Path] = []
    for entry in paths or ["."]:
        start = root / entry
        if not _inside(start, root):
            raise ConfigError(f"discovery.paths entry '{entry}' is outside the project directory.")
        if start.exists():
            starts.append(start)

    files: set[Path] = set()
    notes: list[str] = []
    for start in starts:
        candidates: list[Path] = [start] if start.is_file() else []
        if start.is_dir():
            for directory, subdirs, names in os.walk(start, followlinks=False):
                subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS)
                candidates.extend(Path(directory) / name for name in names)
        for path in candidates:
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in excluded:
                continue
            if not resolved.is_relative_to(root):
                notes.append(f"Skipped {path.name}: symlink points outside the project.")
                continue
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                notes.append(f"Skipped {path.relative_to(root).as_posix()}: larger than 2 MB.")
                continue
            files.add(path)

    ordered = sorted(files)
    if len(ordered) > MAX_FILES:
        notes.append(
            f"Scanned the first {MAX_FILES} of {len(ordered)} files. "
            "Narrow discovery.paths in fmaws.yaml."
        )
        ordered = ordered[:MAX_FILES]
    return ordered, notes
