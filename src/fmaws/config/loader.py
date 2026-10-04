"""Load ``fmaws.yaml`` and turn its declared resources into HIGH-confidence requirements."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from fmaws.config.schema import Config, S3ResourceConfig
from fmaws.errors import ConfigError
from fmaws.models.requirement import Confidence, ResourceRequirement, SourceRef
from fmaws.policy import catalog, s3
from fmaws.utils.text import find_line

PROJECT_CONFIG = "fmaws.yaml"
USER_CONFIG = Path("~/.config/fmaws/config.yaml")
MAX_CONFIG_BYTES = 1_000_000
_DECLARED = "Declared in configuration"


def _read_yaml(path: Path) -> tuple[dict[str, Any], str]:
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path} is too large to be a configuration file.")
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc.strerror}.") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {str(exc).splitlines()[0]}") from exc
    if data is None:
        return {}, text
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level.")
    return data, text


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class LoadedConfig:
    def __init__(self, config: Config, path: Path | None, text: str) -> None:
        self.config = config
        self.path = path
        self.text = text


def load_config(project_root: Path, explicit: Path | None = None) -> LoadedConfig:
    """Project configuration layered over the optional user-level defaults."""
    path = explicit or project_root / PROJECT_CONFIG
    if explicit and not explicit.is_file():
        raise ConfigError(f"Configuration file {explicit} does not exist.")
    data: dict[str, Any] = {}
    user = USER_CONFIG.expanduser()
    if user.is_file():
        data = _read_yaml(user)[0]
    text = ""
    found: Path | None = None
    if path.is_file():
        project_data, text = _read_yaml(path)
        data = _deep_merge(data, project_data)
        found = path
    try:
        return LoadedConfig(Config.model_validate(data), found, text)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"Invalid configuration in {path}: {problems}") from exc


def _names(entry: dict[str, Any], key: str, service: str) -> list[str]:
    singular, plural = entry.get(key), entry.get(f"{key}s")
    names = ([singular] if singular is not None else []) + list(plural or [])
    if not names or not all(isinstance(n, str) and n for n in names):
        raise ConfigError(f"resources.{service}: each entry needs '{key}' (or '{key}s').")
    return names


def requirements_from_config(loaded: LoadedConfig) -> list[ResourceRequirement]:
    source_file = loaded.path.name if loaded.path else PROJECT_CONFIG
    requirements: list[ResourceRequirement] = []

    def source(needle: str) -> SourceRef:
        return SourceRef(file=source_file, line=find_line(loaded.text, needle))

    for service, entries in sorted(loaded.config.resources.items()):
        for raw in entries:
            if service == "s3":
                try:
                    entry = S3ResourceConfig.model_validate(raw)
                except ValidationError as exc:
                    first = exc.errors()[0]
                    where = ".".join(str(p) for p in first["loc"])
                    raise ConfigError(f"resources.s3: {where}: {first['msg']}") from exc
                requirements.append(
                    ResourceRequirement(
                        service="s3",
                        resource=s3.bucket_name(entry.bucket),
                        intents=tuple(entry.actions),
                        confidence=Confidence.HIGH,
                        source=source(entry.bucket),
                        reason=_DECLARED,
                        options=entry.model_dump(exclude={"bucket", "actions"}),
                    )
                )
                continue
            definition = catalog.get(service)
            intents = tuple(raw.get("actions") or definition.default_intents)
            for intent in intents:
                definition.actions_for(intent)
            options = {k: raw[k] for k in ("kms_key",) if raw.get(k)}
            for name in _names(raw, definition.config_key, service):
                requirements.append(
                    ResourceRequirement(
                        service=service,
                        resource=name,
                        intents=intents,
                        confidence=Confidence.HIGH,
                        source=source(name),
                        reason=_DECLARED,
                        options=options,
                    )
                )
    return requirements
