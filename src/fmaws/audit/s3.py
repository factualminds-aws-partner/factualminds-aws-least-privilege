"""S3 analyzer: public exposure first, then cross-account access, then defense in depth."""

import fnmatch
from typing import Any

from fmaws.audit import policies
from fmaws.audit.base import AuditContext, register
from fmaws.audit.findings import make, shown
from fmaws.models.finding import Finding, Severity

_BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)
_WRITE = (
    "s3:PutObject", "s3:PutObjectAcl", "s3:PutObjectTagging", "s3:PutBucketPolicy",
    "s3:PutBucketAcl", "s3:PutBucketWebsite", "s3:PutBucketCORS", "s3:PutBucketVersioning",
    "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
    "s3:PutEncryptionConfiguration", "s3:PutBucketPublicAccessBlock", "s3:ReplicateObject",
    "s3:RestoreObject", "s3:AbortMultipartUpload",
)  # fmt: skip
_DELETE = (
    "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:DeleteBucketPolicy",
)  # fmt: skip
# Defense-in-depth findings are reported once for all affected buckets, not once per bucket.
_AGGREGATED = (
    "S3_BUCKET_BPA_DISABLED", "S3_ACLS_ENABLED", "S3_VERSIONING_DISABLED", "S3_LOGGING_DISABLED",
)  # fmt: skip


class S3:
    name = "s3"
    regional = False

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        buckets = [b["Name"] for b in ctx.pages("s3", "list_buckets", "Buckets")]
        account_bpa = (
            ctx.optional(
                "s3control",
                "get_public_access_block",
                ctx.home_region,
                missing=("NoSuchPublicAccessBlockConfiguration",),
                AccountId=ctx.account,
            )
            or {}
        ).get("PublicAccessBlockConfiguration", {})

        findings: list[Finding] = []
        off = [flag for flag in _BPA_FLAGS if not account_bpa.get(flag)]
        if off:
            findings.append(
                make(
                    "S3_ACCOUNT_BPA_DISABLED",
                    f"arn:{ctx.partition}:s3:::*",
                    f"Not enabled at account level: {', '.join(off)}.",
                    evidence={"disabled": off},
                )
            )

        aggregated: dict[str, list[str]] = {rule: [] for rule in _AGGREGATED}
        buckets.sort()
        results = ctx.map(lambda name: self._bucket(ctx, name, account_bpa), buckets)
        for name, (found, flags) in zip(buckets, results, strict=True):
            findings.extend(found)
            for rule in flags:
                aggregated[rule].append(name)
        for rule, names in aggregated.items():
            if names:
                findings.append(
                    make(
                        rule,
                        f"{len(names)} bucket(s)",
                        f"Affected: {shown(names)}.",
                        evidence={"buckets": names},
                    )
                )
        return findings

    def _bucket(
        self, ctx: AuditContext, name: str, account_bpa: dict[str, Any]
    ) -> tuple[list[Finding], list[str]]:
        arn = f"arn:{ctx.partition}:s3:::{name}"
        trusted = set(ctx.config.audit.trusted_accounts)

        def get(operation: str, *missing: str) -> dict[str, Any] | None:
            return ctx.optional("s3", operation, missing=missing, Bucket=name)

        bucket_bpa = (
            get("get_public_access_block", "NoSuchPublicAccessBlockConfiguration") or {}
        ).get("PublicAccessBlockConfiguration", {})
        policy = (get("get_bucket_policy", "NoSuchBucketPolicy") or {}).get("Policy")
        acl = get("get_bucket_acl") or {}
        ownership = get("get_bucket_ownership_controls", "OwnershipControlsNotFoundError")
        versioning = get("get_bucket_versioning")
        logging = get("get_bucket_logging")
        encryption = get("get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError")

        def blocked(flag: str) -> bool:
            return bool(account_bpa.get(flag) or bucket_bpa.get(flag))

        rules = (ownership or {}).get("OwnershipControls", {}).get("Rules", [])
        acls_disabled = any(r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules)

        public: set[str] = set()  # "read", "write", "delete"
        overridden = False
        conditioned = False
        external: dict[str, bool] = {}  # account -> can change data
        for statement in ctx.statements(policy):
            writes = policies.allows(statement, *_WRITE)
            deletes = policies.allows(statement, *_DELETE)
            for account in policies.external_accounts(statement, ctx.account, trusted):
                external[account] = external.get(account, False) or writes or deletes
            if not policies.is_public(statement) or policies.is_restricted(statement):
                continue
            if policies.is_conditioned(statement):
                conditioned = True
                continue
            if blocked("RestrictPublicBuckets"):
                overridden = True
                continue
            if writes:
                public.add("write")
            if deletes:
                public.add("delete")
            # Whatever else a public statement grants (GetObject, GetObjectVersion, GetBucketAcl,
            # an action fmaws does not know) exposes the bucket: never let it go unreported.
            if not (writes or deletes) or policies.allows(
                statement, "s3:GetObject", "s3:ListBucket"
            ):
                public.add("read")

        if not acls_disabled:
            for grant in acl.get("Grants", []):
                if grant.get("Grantee", {}).get("URI") not in _PUBLIC_GROUPS:
                    continue
                if blocked("IgnorePublicAcls"):
                    overridden = True
                elif grant.get("Permission") in ("WRITE", "WRITE_ACP", "FULL_CONTROL"):
                    public.add("write")
                else:
                    public.add("read")

        findings: list[Finding] = []
        if "write" in public:
            findings.append(
                make("S3_PUBLIC_WRITE", arn, "Anonymous users may upload or modify objects.")
            )
        if "delete" in public:
            findings.append(make("S3_PUBLIC_DELETE", arn, "Anonymous users may delete objects."))
        if "read" in public:
            intentional = any(
                fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(arn, p)
                for p in ctx.config.audit.intentional_public
            )
            findings.append(
                make(
                    "S3_PUBLIC_READ_INTENTIONAL" if intentional else "S3_PUBLIC_READ",
                    arn,
                    "Anyone can read or list objects in this bucket.",
                )
            )
        if overridden and not public:
            findings.append(
                make(
                    "S3_PUBLIC_BLOCKED",
                    arn,
                    "The bucket policy or ACL grants public access; Block Public Access "
                    "currently overrides it.",
                )
            )
        if conditioned:
            findings.append(
                make(
                    "S3_WILDCARD_PRINCIPAL_CONDITIONED",
                    arn,
                    'A statement allows Principal "*" limited only by its condition.',
                )
            )
        if external:
            writers = sorted(a for a, modifies in external.items() if modifies)
            findings.append(
                make(
                    "S3_CROSS_ACCOUNT_ACCESS",
                    arn,
                    f"External account(s): {', '.join(sorted(external))}."
                    + (f" Can modify data: {', '.join(writers)}." if writers else " Read only."),
                    severity=None if writers else Severity.LOW,
                    evidence={"accounts": sorted(external)},
                )
            )
        if encryption == {}:
            findings.append(
                make("S3_ENCRYPTION_MISSING", arn, "No default encryption is configured.")
            )

        flags: list[str] = []
        if not all(blocked(flag) for flag in _BPA_FLAGS):
            flags.append("S3_BUCKET_BPA_DISABLED")
        if ownership is not None and not acls_disabled:
            flags.append("S3_ACLS_ENABLED")
        if versioning is not None and versioning.get("Status") != "Enabled":
            flags.append("S3_VERSIONING_DISABLED")
        if logging is not None and "LoggingEnabled" not in logging:
            flags.append("S3_LOGGING_DISABLED")
        return findings, flags


register(S3())
