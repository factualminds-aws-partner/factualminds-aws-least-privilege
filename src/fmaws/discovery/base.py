"""Detector interface, registry and the discovery run."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from fmaws.discovery.walker import walk
from fmaws.errors import ConfigError
from fmaws.models.requirement import ResourceRequirement


@dataclass
class Detection:
    """What one detector found in one file."""

    requirements: list[ResourceRequirement] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)

    def merge(self, other: "Detection") -> None:
        self.requirements.extend(other.requirements)
        self.notes.extend(other.notes)
        self.regions.extend(other.regions)
        self.accounts.extend(other.accounts)


class ResourceDetector(Protocol):
    name: str

    def matches(self, path: Path) -> bool: ...

    def detect(self, relative_path: str, text: str) -> Detection: ...


DETECTORS: dict[str, ResourceDetector] = {}


def register(detector: ResourceDetector) -> None:
    DETECTORS[detector.name] = detector


def discover(
    root: Path,
    paths: list[str] | None = None,
    enabled: list[str] | None = None,
    exclude: list[Path] | None = None,
) -> Detection:
    """Run every enabled detector over the project. One broken file never aborts the run."""
    from fmaws.discovery import detectors  # noqa: F401  (registers the built-in detectors)

    unknown = sorted(set(enabled or []) - set(DETECTORS))
    if unknown:
        raise ConfigError(
            f"Unknown detector '{unknown[0]}' in discovery.detectors. "
            f"Available: {', '.join(sorted(DETECTORS))}."
        )
    active = [d for name, d in sorted(DETECTORS.items()) if not enabled or name in enabled]
    result = Detection()
    files, notes = walk(root, paths or [], exclude or [])
    result.notes.extend(notes)
    for path in files:
        matching = [d for d in active if d.matches(path)]
        if not matching:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.notes.append(f"Skipped {relative}: {exc.strerror}.")
            continue
        for detector in matching:
            try:
                result.merge(detector.detect(relative, text))
            except Exception as exc:  # noqa: BLE001  malformed input must not abort discovery
                result.notes.append(
                    f"Skipped {relative} ({detector.name}): {type(exc).__name__} while parsing."
                )
    return result
