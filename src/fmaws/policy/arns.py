"""ARN construction, parsing and IAM wildcard matching."""

import re
from dataclasses import dataclass
from functools import cache, lru_cache

from fmaws.errors import ConfigError
from fmaws.models.policy import Conditions
from fmaws.policy import catalog
from fmaws.policy.catalog import ServiceDefinition

# Resource names may not carry IAM wildcards, whitespace or quotes: a name is data, never a pattern.
NAME_RE = re.compile(r"[A-Za-z0-9_+=,.@/:#-]+")


REGION_RE = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")
PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
# A value no real resource has: a pattern that matches a name built from it matches everything.
PROBE = "fmaws-probe-7f3a"


@dataclass(frozen=True)
class ArnContext:
    """The fields every generated ARN shares. Each is validated: a stray ``:`` or wildcard in
    one of them would shift or widen the ARN fields that follow it."""

    partition: str = "aws"
    region: str = "*"
    account: str = "*"

    def __post_init__(self) -> None:
        if self.partition not in PARTITIONS:
            raise ConfigError(f"Invalid AWS partition '{self.partition}'.")
        if self.region != "*" and not REGION_RE.fullmatch(self.region):
            raise ConfigError(f"Invalid AWS region '{self.region}'.")
        if self.account != "*" and not re.fullmatch(r"\d{12}", self.account):
            raise ConfigError(f"Invalid AWS account ID '{self.account}'.")


SQS_URL_RE = re.compile(
    r"https://sqs\.([a-z0-9-]+)\.amazonaws\.com/(\d{12})/([A-Za-z0-9_-]+(?:\.fifo)?)"
)


def sqs_url_to_arn(url: str, partition: str = "aws") -> str | None:
    """The queue ARN for a queue URL, which is what applications usually have in configuration."""
    match = SQS_URL_RE.fullmatch(url)
    return f"arn:{partition}:sqs:{match[1]}:{match[2]}:{match[3]}" if match else None


def validate_name(name: str, what: str) -> str:
    if "://" in name:
        raise ConfigError(f"Invalid {what} '{name}': use the resource name or ARN, not a URL.")
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


def kms_via_service(service: str, ctx: ArnContext, include_conditions: bool) -> Conditions:
    """Condition that limits a KMS grant to requests made through one AWS service."""
    if not include_conditions or ctx.region == "*":
        return {}
    return {"StringEquals": {"kms:ViaService": [f"{service}.{ctx.region}.amazonaws.com"]}}


@lru_cache(maxsize=4096)
def _wildcard_regex(pattern: str) -> re.Pattern[str]:
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(regex, re.DOTALL)


def iam_match(pattern: str, value: str) -> bool:
    """IAM wildcard semantics: ``*`` matches any run of characters, ``?`` exactly one."""
    if "*" not in pattern and "?" not in pattern:
        return pattern == value
    return _wildcard_regex(pattern).fullmatch(value) is not None
