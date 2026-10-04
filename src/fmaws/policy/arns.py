"""ARN construction, parsing and IAM wildcard matching."""

import re
from dataclasses import dataclass
from functools import cache

from fmaws.errors import ConfigError
from fmaws.policy import catalog
from fmaws.policy.catalog import ServiceDefinition

# Resource names may not carry IAM wildcards, whitespace or quotes: a name is data, never a pattern.
NAME_RE = re.compile(r"[A-Za-z0-9_+=,.@/:#-]+")


@dataclass(frozen=True)
class ArnContext:
    partition: str = "aws"
    region: str = "*"
    account: str = "*"


def validate_name(name: str, what: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise ConfigError(
            f"Invalid {what} '{name}': names may not contain wildcards, spaces or quotes."
        )
    return name


@cache
def _template_regex(template: str) -> re.Pattern[str]:
    pattern = re.escape(template).replace(r"\?", ".")
    for placeholder, group in (
        ("partition", r"(?P<partition>aws|aws-cn|aws-us-gov)"),
        ("region", r"(?P<region>[a-z0-9-]*)"),
        ("account", r"(?P<account>\d{12}|)"),
        ("name", r"(?P<name>[A-Za-z0-9_+=,.@/:#-]+?)"),
    ):
        pattern = pattern.replace(re.escape("{" + placeholder + "}"), group)
    # A trailing ":*" (log groups) is optional in ARNs found in the wild.
    if pattern.endswith(r":\*"):
        pattern = pattern[: -len(r":\*")] + r"(?::\*)?"
    return re.compile(pattern)


def parse_arn(definition: ServiceDefinition, arn: str) -> dict[str, str] | None:
    """Return partition/region/account/name if ``arn`` is an ARN of this service's resource."""
    match = _template_regex(definition.arn_template).fullmatch(arn)
    return match.groupdict() if match else None


def build_arn(definition: ServiceDefinition, name: str, ctx: ArnContext) -> str:
    return definition.arn_template.format(
        partition=ctx.partition, region=ctx.region, account=ctx.account, name=name
    )


def kms_key_arn(key: str, ctx: ArnContext) -> str:
    definition = catalog.get("kms")
    if key.startswith("arn:"):
        if parse_arn(definition, key) is None:
            raise ConfigError(f"Malformed KMS key ARN '{key}'.")
        return key
    if key.startswith("alias/"):
        raise ConfigError(
            f"kms_key '{key}' is an alias: IAM policies authorize the key ARN or key ID."
        )
    return build_arn(definition, validate_name(key, "KMS key"), ctx)


def iam_match(pattern: str, value: str) -> bool:
    """IAM wildcard semantics: ``*`` matches any run of characters, ``?`` exactly one."""
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, value, re.DOTALL) is not None
