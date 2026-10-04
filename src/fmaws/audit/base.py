"""Audit runtime: allow-listed AWS access, analyzer registry and a failure-tolerant runner."""

import fnmatch
import threading
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError

from fmaws.audit import policies
from fmaws.aws.session import AWSClientProvider
from fmaws.config.schema import Config
from fmaws.errors import AwsAuthError, ConfigError
from fmaws.models.finding import Finding, Severity
from fmaws.models.report import AnalyzerStatus

# Every AWS operation the audit may call, and the IAM action it requires. Anything else is
# refused at runtime. permissions/audit-readonly-policy.json is generated from this table.
OPERATIONS: dict[tuple[str, str], str] = {
    ("iam", "get_account_summary"): "iam:GetAccountSummary",
    ("iam", "generate_credential_report"): "iam:GenerateCredentialReport",
    ("iam", "get_credential_report"): "iam:GetCredentialReport",
    ("iam", "get_account_authorization_details"): "iam:GetAccountAuthorizationDetails",
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    ("s3control", "get_public_access_block"): "s3:GetAccountPublicAccessBlock",
    ("s3", "get_public_access_block"): "s3:GetBucketPublicAccessBlock",
    ("s3", "get_bucket_policy"): "s3:GetBucketPolicy",
    ("s3", "get_bucket_policy_status"): "s3:GetBucketPolicyStatus",
    ("s3", "get_bucket_acl"): "s3:GetBucketAcl",
    ("s3", "get_bucket_ownership_controls"): "s3:GetBucketOwnershipControls",
    ("s3", "get_bucket_versioning"): "s3:GetBucketVersioning",
    ("s3", "get_bucket_logging"): "s3:GetBucketLogging",
    ("s3", "get_bucket_encryption"): "s3:GetEncryptionConfiguration",
    ("ec2", "describe_regions"): "ec2:DescribeRegions",
    ("ec2", "describe_security_groups"): "ec2:DescribeSecurityGroups",
    ("ec2", "describe_network_interfaces"): "ec2:DescribeNetworkInterfaces",
    ("cloudtrail", "describe_trails"): "cloudtrail:DescribeTrails",
    ("cloudtrail", "get_trail_status"): "cloudtrail:GetTrailStatus",
    ("cloudtrail", "get_event_selectors"): "cloudtrail:GetEventSelectors",
    ("secretsmanager", "list_secrets"): "secretsmanager:ListSecrets",
    ("kms", "list_keys"): "kms:ListKeys",
    ("kms", "list_aliases"): "kms:ListAliases",
    ("kms", "get_key_policy"): "kms:GetKeyPolicy",
    ("rds", "describe_db_instances"): "rds:DescribeDBInstances",
}

_DENIED = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
    "AuthorizationErrorException", "MethodNotAllowed", "AllAccessDisabled",
}  # fmt: skip
_EXPIRED = {"ExpiredToken", "ExpiredTokenException", "RequestExpired"}
# With a working identity, these mean the Region is not enabled for the account.
_REGION = {"OptInRequired", "AuthFailure", "UnrecognizedClientException", "InvalidClientTokenId"}

COMPLETED, SKIPPED, FAILED = "completed", "skipped", "failed"
UNREADABLE = "reading a policy"


class AuditDenied(Exception):
    def __init__(self, permission: str) -> None:
        super().__init__(permission)
        self.permission = permission


class RegionUnavailable(Exception):
    pass


@dataclass
class AuditContext:
    provider: AWSClientProvider
    account: str
    regions: list[str]
    config: Config
    partition: str = "aws"
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    denied: Counter[str] = field(default_factory=Counter)
    _cache: dict[str, tuple[bool, Any]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    @property
    def home_region(self) -> str:
        return self.regions[0]

    def _client(self, service: str, operation: str, region: str | None) -> Any:
        if (service, operation) not in OPERATIONS:
            raise RuntimeError(f"{service}.{operation} is not an allow-listed audit operation")
        with self._lock:
            return self.provider.client(service, region)

    def _guard(self, service: str, operation: str, invoke: Callable[[], Any]) -> Any:
        try:
            return invoke()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _EXPIRED:
                raise AwsAuthError(
                    "AWS credentials expired during the audit. Refresh them and retry."
                ) from exc
            if code in _DENIED:
                raise AuditDenied(OPERATIONS[(service, operation)]) from exc
            if code in _REGION:
                raise RegionUnavailable(code) from exc
            raise
        except BotoCoreError as exc:
            if type(exc).__name__ in ("EndpointConnectionError", "ConnectTimeoutError"):
                raise RegionUnavailable(type(exc).__name__) from exc
            raise

    def call(self, service: str, operation: str, region: str | None = None, **kwargs: Any) -> Any:
        client = self._client(service, operation, region)
        return self._guard(service, operation, lambda: getattr(client, operation)(**kwargs))

    def all_pages(
        self, service: str, operation: str, region: str | None = None, **kwargs: Any
    ) -> list[dict[str, Any]]:
        client = self._client(service, operation, region)
        if not client.can_paginate(operation):
            return [self.call(service, operation, region, **kwargs)]
        return self._guard(  # type: ignore[no-any-return]
            service, operation, lambda: list(client.get_paginator(operation).paginate(**kwargs))
        )

    def pages(
        self, service: str, operation: str, key: str, region: str | None = None, **kwargs: Any
    ) -> list[Any]:
        pages = self.all_pages(service, operation, region, **kwargs)
        return [item for page in pages for item in page.get(key, [])]

    def optional(
        self,
        service: str,
        operation: str,
        region: str | None = None,
        missing: tuple[str, ...] = (),
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """A per-resource call. ``{}`` when the thing does not exist, ``None`` when unknown.

        A denied or failing call is counted and reported, never read as "nothing there".
        """
        try:
            result: dict[str, Any] = self.call(service, operation, region, **kwargs)
            return result
        except AuditDenied as exc:
            with self._lock:
                self.denied[exc.permission] += 1
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in missing:
                return {}
            with self._lock:
                self.denied[OPERATIONS[(service, operation)]] += 1
        except (RegionUnavailable, BotoCoreError):
            with self._lock:
                self.denied[OPERATIONS[(service, operation)]] += 1
        return None

    def statements(self, document: Any) -> list[dict[str, Any]]:
        """Allow statements of a policy. An unreadable policy is counted, never read as empty."""
        try:
            return policies.allow_statements(document)
        except policies.UnreadablePolicy:
            with self._lock:
                self.denied[UNREADABLE] += 1
            return []

    def cached(self, key: str, factory: Callable[[], Any]) -> Any:
        """Shared data fetched once per run. A failure is remembered and raised again."""
        with self._lock:
            if key not in self._cache:
                try:
                    self._cache[key] = (True, factory())
                except Exception as exc:  # noqa: BLE001  re-raised below for every consumer
                    self._cache[key] = (False, exc)
            ok, value = self._cache[key]
        if not ok:
            raise value
        return value

    def map(self, function: Callable[[Any], Any], items: list[Any]) -> list[Any]:
        """Bounded concurrency. Results keep the order of ``items``."""
        workers = min(self.config.audit.concurrency, len(items))
        if workers <= 1:
            return [function(item) for item in items]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(function, items))

    def days_since(self, moment: datetime | None) -> int | None:
        if moment is None:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return (self.now - moment).days


class AccountAuditor(Protocol):
    name: str
    regional: bool

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]: ...


ANALYZERS: dict[str, AccountAuditor] = {}


def register(analyzer: AccountAuditor) -> None:
    ANALYZERS[analyzer.name] = analyzer


def _load_analyzers() -> None:
    from fmaws.audit import cloudtrail, data, iam, network, s3  # noqa: F401


def resolve_regions(
    provider: AWSClientProvider, config: Config, region: str | None, all_regions: bool
) -> list[str]:
    if all_regions:
        ctx = AuditContext(provider, "", [region or provider.region or "us-east-1"], config)
        try:
            found = ctx.pages("ec2", "describe_regions", "Regions", ctx.home_region)
        except AuditDenied as exc:
            raise AwsAuthError(f"--all-regions needs {exc.permission}.") from exc
        return sorted(r["RegionName"] for r in found)
    regions = [region] if region else (config.audit.regions or [])
    regions = regions or [r for r in (config.aws.region, provider.region) if r][:1]
    if not regions:
        raise ConfigError("No AWS region to audit. Pass --region or --all-regions.")
    return list(regions)


def _describe(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return f"AWS returned {exc.response.get('Error', {}).get('Code', 'an error')}"
    if isinstance(exc, RegionUnavailable):
        return f"Region not available ({exc})"
    return f"{type(exc).__name__}"


def _run_regional(
    analyzer: AccountAuditor, ctx: AuditContext
) -> tuple[list[Finding], AnalyzerStatus]:
    def one(region: str) -> tuple[list[Finding], Exception | None]:
        try:
            return analyzer.run(ctx, region), None
        except AwsAuthError:
            raise
        except Exception as exc:  # noqa: BLE001  one Region must not abort the others
            return [], exc

    results = ctx.map(one, ctx.regions)
    findings = [f for found, _ in results for f in found]
    problems = {r: exc for r, (_, exc) in zip(ctx.regions, results, strict=True) if exc}
    if not problems:
        return findings, AnalyzerStatus(name=analyzer.name, status=COMPLETED)
    details = "; ".join(
        f"{region}: missing permission {exc.permission}"
        if isinstance(exc, AuditDenied)
        else f"{region}: {_describe(exc)}"
        for region, exc in sorted(problems.items())
    )
    if len(problems) < len(ctx.regions):
        return findings, AnalyzerStatus(
            name=analyzer.name, status=COMPLETED, detail=f"incomplete, {details}"
        )
    denied = all(isinstance(exc, AuditDenied | RegionUnavailable) for exc in problems.values())
    return [], AnalyzerStatus(
        name=analyzer.name, status=SKIPPED if denied else FAILED, detail=details
    )


def run_audit(ctx: AuditContext) -> tuple[list[Finding], list[AnalyzerStatus]]:
    """Run every enabled analyzer. A failure in one never aborts the others."""
    _load_analyzers()
    enabled = ctx.config.audit.enabled_analyzers
    unknown = sorted(set(enabled) - set(ANALYZERS))
    if unknown:
        raise ConfigError(
            f"Unknown analyzer '{unknown[0]}' in audit.enabled_analyzers. "
            f"Available: {', '.join(ANALYZERS)}."
        )
    findings: list[Finding] = []
    statuses: list[AnalyzerStatus] = []
    for name, analyzer in ANALYZERS.items():
        if enabled and name not in enabled:
            statuses.append(
                AnalyzerStatus(name=name, status=SKIPPED, detail="disabled in configuration")
            )
            continue
        before = Counter(ctx.denied)
        try:
            if analyzer.regional:
                found, status = _run_regional(analyzer, ctx)
            else:
                found, status = analyzer.run(ctx, None), AnalyzerStatus(name=name, status=COMPLETED)
        except AwsAuthError:
            raise
        except AuditDenied as exc:
            found = []
            status = AnalyzerStatus(
                name=name, status=SKIPPED, detail=f"missing permission {exc.permission}"
            )
        except Exception as exc:  # noqa: BLE001  one analyzer must not abort the audit
            found, status = [], AnalyzerStatus(name=name, status=FAILED, detail=_describe(exc))
        partial = ctx.denied - before
        if partial and status.status == COMPLETED:
            gaps = ", ".join(f"{p} failed for {n} resource(s)" for p, n in sorted(partial.items()))
            status.detail = "; ".join(d for d in (status.detail, f"incomplete, {gaps}") if d)
        findings.extend(found)
        statuses.append(status)
    return findings, statuses


def apply_config(findings: list[Finding], config: Config) -> tuple[list[Finding], int]:
    """Severity overrides, then ignored findings and resources. Returns kept and ignored count."""
    audit = config.audit
    kept: list[Finding] = []
    for finding in findings:
        if finding.id in audit.ignored_findings or any(
            fnmatch.fnmatchcase(finding.resource, pattern) for pattern in audit.ignored_resources
        ):
            continue
        override = audit.severity_overrides.get(finding.id)
        if override:
            finding = finding.model_copy(update={"severity": Severity(override.upper())})
        kept.append(finding)
    kept.sort(key=lambda f: (-f.severity.rank, f.id, f.resource))
    return kept, len(findings) - len(kept)


def is_incomplete(status: AnalyzerStatus) -> bool:
    """The analyzer did not look at everything, for a reason other than configuration."""
    if status.status == FAILED:
        return True
    if status.status == SKIPPED:
        return status.detail != "disabled in configuration"
    return "incomplete" in status.detail


def permission_manifest() -> dict[str, Any]:
    """The read-only IAM policy that lets every analyzer run."""
    actions = sorted({*OPERATIONS.values(), "sts:GetCallerIdentity"})
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "FmawsAuditReadOnly", "Effect": "Allow", "Action": actions, "Resource": "*"}
        ],
    }
