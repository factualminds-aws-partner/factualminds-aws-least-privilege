"""Typed model of ``fmaws.yaml``. Every section is optional."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApplicationConfig(BaseModel):
    name: str | None = None
    environment: str | None = None


class AwsConfig(BaseModel):
    region: str | None = None
    account_id: str | None = Field(default=None, pattern=r"^\d{12}$")
    profile: str | None = None
    partition: Literal["aws", "aws-cn", "aws-us-gov"] = "aws"


class PolicyConfig(BaseModel):
    include_conditions: bool = True
    # Severity of ``service:*`` actions found by local validation.
    wildcard_action_threshold: Literal["info", "warning", "error"] = "warning"


class DiscoveryConfig(BaseModel):
    enabled: bool = True
    # Files or directories relative to the project root. Empty means the whole project.
    paths: list[str] = Field(default_factory=list)
    # Detector names to run. Empty means all.
    detectors: list[str] = Field(default_factory=list)


class S3ResourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bucket: str
    prefixes: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=lambda: ["read"])
    multipart: bool = False
    versioned: bool = False
    bucket_location: bool = False
    kms_key: str | None = None
    # Owning account, for buckets in another account.
    account_id: str | None = None


SeverityName = Literal["critical", "high", "medium", "low", "info"]


class ThresholdConfig(BaseModel):
    fail_on: list[SeverityName] = Field(default_factory=list)


class AuditConfig(BaseModel):
    # Analyzer names to run. Empty means all.
    enabled_analyzers: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    ignored_findings: list[str] = Field(default_factory=list)
    # Resource ARNs or shell-style patterns whose findings are dropped.
    ignored_resources: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, SeverityName] = Field(default_factory=dict)
    fail_on: list[SeverityName] = Field(default_factory=list)
    # "production" or anything else. Defaults to application.environment, then production.
    environment: str | None = None
    production: ThresholdConfig = Field(default_factory=ThresholdConfig)
    non_production: ThresholdConfig = Field(default_factory=ThresholdConfig)
    # Buckets (names, ARNs or patterns) that are public on purpose.
    intentional_public: list[str] = Field(default_factory=list)
    # Account IDs inside your trust boundary: cross-account access to them is not reported.
    trusted_accounts: list[str] = Field(default_factory=list)
    max_access_key_age_days: int = Field(default=90, ge=1)
    unused_days: int = Field(default=90, ge=1)
    concurrency: int = Field(default=4, ge=1, le=16)

    @field_validator("fail_on", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        return [value] if isinstance(value, str) else value


class ObserveConfig(BaseModel):
    # Role or user the application runs as (ARN).
    principal: str | None = None
    days: int = Field(default=30, ge=1, le=400)
    # An unused permission is only dropped from the recommended policy after this many days.
    min_days_for_removal: int = Field(default=90, ge=1)
    cloudtrail: bool = False
    max_events: int = Field(default=2000, ge=50, le=50_000)


class Config(BaseModel):
    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    aws: AwsConfig = Field(default_factory=AwsConfig)
    resources: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    observe: ObserveConfig = Field(default_factory=ObserveConfig)

    @property
    def audit_fail_on(self) -> list[str]:
        """Severities that fail an audit: the environment's list, else the general one."""
        audit = self.audit
        environment = audit.production if self.is_production else audit.non_production
        return list(environment.fail_on or audit.fail_on)

    @property
    def is_production(self) -> bool:
        environment = self.audit.environment or self.application.environment or "production"
        return environment.lower() in ("production", "prod")
