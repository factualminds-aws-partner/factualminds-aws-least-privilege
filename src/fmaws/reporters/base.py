"""Reporter registry. A reporter turns a Report into text; the CLI redacts and prints it."""

from collections.abc import Callable
from importlib import import_module

from fmaws.errors import ConfigError
from fmaws.models.report import MISSING, UNKNOWN, UNUSED, USED, Report

Reporter = Callable[[Report], str]
REPORTERS: dict[str, Reporter] = {}
FORMATS = ("console", "json", "markdown", "sarif")

CANDIDATE_NOTICE = (
    "This is a candidate policy derived from configuration and static analysis. It cannot "
    "guarantee that the application never needs a permission that was not declared or detected. "
    "Test it in a non-production environment before relying on it."
)


UNUSED_NOTICE = (
    "Unused during the observation period is not the same as unnecessary. A permission used by "
    "a monthly job, an error path or a disaster recovery procedure looks unused in a short "
    "window. Unknown means no evidence source can tell either way."
)
OBSERVE_LABELS = (
    (MISSING, "Potentially missing permission"),
    (UNUSED, "Unused permission"),
    (UNKNOWN, "Unknown permission"),
    (USED, "Used permission"),
)


def register(name: str) -> Callable[[Reporter], Reporter]:
    def decorator(reporter: Reporter) -> Reporter:
        REPORTERS[name] = reporter
        return reporter

    return decorator


def render(report: Report, fmt: str) -> str:
    if fmt not in FORMATS:
        raise ConfigError(f"Unknown format '{fmt}'. Supported: {', '.join(FORMATS)}.")
    import_module(f"fmaws.reporters.{fmt}")  # registers the reporter; only the one needed
    return REPORTERS[fmt](report)
