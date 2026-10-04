"""S3 least-privilege engine.

Follows S3 authorization semantics: bucket-level actions (``s3:ListBucket``) are authorized on
the bucket ARN and narrowed with the ``s3:prefix`` condition, object-level actions on object
ARNs. A folder permission is never widened to the whole bucket.
"""

import re
from dataclasses import dataclass, field

from fmaws.errors import ConfigError
from fmaws.models.policy import Conditions, Explanation, Statement
from fmaws.models.requirement import ResourceRequirement
from fmaws.policy.arns import ArnContext, kms_key_arn

BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
INTENTS = ("read", "write", "delete", "list")
DEFAULT_INTENTS = ("read",)

_OBJECT_ACTIONS = {
    "read": ("s3:GetObject",),
    "write": ("s3:PutObject",),
    "delete": ("s3:DeleteObject",),
}
_VERSIONED_OBJECT_ACTIONS = {
    "read": ("s3:GetObjectVersion",),
    "delete": ("s3:DeleteObjectVersion",),
}
# Needed to abort and to resume/complete multipart uploads. Initiating, uploading parts and
# completing are all authorized by s3:PutObject.
_MULTIPART_ACTIONS = ("s3:AbortMultipartUpload", "s3:ListMultipartUploadParts")


def bucket_name(value: str) -> str:
    """Accept a bucket name or bucket ARN and return the validated bucket name."""
    name = re.sub(r"^arn:(aws|aws-cn|aws-us-gov):s3:::", "", value)
    if not BUCKET_RE.fullmatch(name):
        raise ConfigError(f"Invalid S3 bucket name '{value}'.")
    return name


def normalize_prefix(prefix: str) -> str:
    """Return ``""`` for the bucket root, otherwise a key prefix without leading slash.

    ``uploads`` and ``uploads/`` are both the folder ``uploads/``. A trailing ``*`` marks a raw
    key prefix (``uploads/img-*`` -> ``uploads/img-``) and is not turned into a folder.
    """
    cleaned = prefix.lstrip("/")
    raw = cleaned.endswith("*")
    cleaned = cleaned.rstrip("*")
    if "*" in cleaned or "?" in cleaned:
        raise ConfigError(
            f"Invalid S3 prefix '{prefix}': wildcards inside a prefix would broaden access."
        )
    if cleaned and not re.fullmatch(r"[^\s\"'\\]+", cleaned):
        raise ConfigError(f"Invalid S3 prefix '{prefix}': whitespace and quotes are not supported.")
    if not cleaned or raw or cleaned.endswith("/"):
        return cleaned
    return cleaned + "/"


@dataclass
class _PrefixAccess:
    object_actions: set[str] = field(default_factory=set)
    list_actions: set[str] = field(default_factory=set)
    explanations: list[Explanation] = field(default_factory=list)


def _single(reqs: list[ResourceRequirement], option: str, bucket: str) -> str | None:
    values = {str(r.options[option]) for r in reqs if r.options.get(option)}
    if len(values) > 1:
        raise ConfigError(f"Conflicting '{option}' values for bucket '{bucket}'.")
    return values.pop() if values else None


def build_bucket(
    bucket: str, reqs: list[ResourceRequirement], ctx: ArnContext, include_conditions: bool = True
) -> list[Statement]:
    """Build the statements for every requirement that targets ``bucket``."""
    bucket = bucket_name(bucket)
    bucket_arn = f"arn:{ctx.partition}:s3:::{bucket}"
    kms_key = _single(reqs, "kms_key", bucket)
    owner = _single(reqs, "account_id", bucket)
    if owner and not re.fullmatch(r"\d{12}", owner):
        raise ConfigError(f"Invalid account_id '{owner}' for bucket '{bucket}'.")

    access: dict[str, _PrefixAccess] = {}
    all_intents: set[str] = set()
    multipart_write = False
    for req in reqs:
        unknown = set(req.intents) - set(INTENTS)
        if unknown:
            raise ConfigError(
                f"Unknown action '{sorted(unknown)[0]}' for s3. "
                f"Supported actions: {', '.join(INTENTS)}."
            )
        all_intents.update(req.intents)
        versioned = bool(req.options.get("versioned"))
        multipart = bool(req.options.get("multipart"))
        multipart_write = multipart_write or (multipart and "write" in req.intents)
        for raw_prefix in req.options.get("prefixes") or [""]:
            prefix = normalize_prefix(str(raw_prefix))
            entry = access.setdefault(prefix, _PrefixAccess())
            for intent in req.intents:
                entry.object_actions.update(_OBJECT_ACTIONS.get(intent, ()))
                if versioned:
                    entry.object_actions.update(_VERSIONED_OBJECT_ACTIONS.get(intent, ()))
            if multipart and "write" in req.intents:
                entry.object_actions.update(_MULTIPART_ACTIONS)
            if "list" in req.intents:
                entry.list_actions.add("s3:ListBucket")
                if versioned:
                    entry.list_actions.add("s3:ListBucketVersions")
            entry.explanations.append(
                Explanation(
                    reason=f"{req.reason}: {', '.join(sorted(req.intents))} on "
                    f"s3://{bucket}/{prefix}*",
                    source=str(req.source),
                    confidence=req.confidence,
                )
            )

    # A nested prefix only keeps what its parents do not already grant.
    effective: dict[str, _PrefixAccess] = {}
    for prefix, entry in access.items():
        parents = [access[p] for p in access if p != prefix and prefix.startswith(p)]
        inherited_objects = set().union(*(p.object_actions for p in parents))
        inherited_lists = set().union(*(p.list_actions for p in parents))
        effective[prefix] = _PrefixAccess(
            entry.object_actions - inherited_objects,
            entry.list_actions - inherited_lists,
            entry.explanations,
        )

    base: Conditions = {}
    notes = ""
    if owner:
        notes = f" Cross-account bucket owned by {owner}: the bucket policy must also allow access."
        if include_conditions:
            base = {"StringEquals": {"s3:ResourceAccount": [owner]}}

    def explain(items: list[Explanation]) -> tuple[Explanation, ...]:
        return tuple(e.model_copy(update={"reason": e.reason + notes}) for e in items)

    statements: list[Statement] = []
    list_groups: dict[frozenset[str], list[str]] = {}
    for prefix in sorted(effective):
        entry = effective[prefix]
        if entry.object_actions:
            statements.append(
                Statement(
                    actions=tuple(sorted(entry.object_actions)),
                    resources=(f"{bucket_arn}/{prefix}*",),
                    conditions=dict(base),
                    explanations=explain(entry.explanations),
                )
            )
        if entry.list_actions:
            list_groups.setdefault(frozenset(entry.list_actions), []).append(prefix)

    for actions, prefixes in sorted(list_groups.items(), key=lambda kv: sorted(kv[0])):
        conditions: Conditions = dict(base)
        if "" not in prefixes:
            conditions["StringLike"] = {"s3:prefix": [f"{p}*" for p in sorted(prefixes)]}
        statements.append(
            Statement(
                actions=tuple(sorted(actions)),
                resources=(bucket_arn,),
                conditions=conditions,
                explanations=explain([e for p in prefixes for e in effective[p].explanations]),
            )
        )

    everything = [e for entry in access.values() for e in entry.explanations]
    if any(req.options.get("bucket_location") for req in reqs):
        statements.append(
            Statement(
                actions=("s3:GetBucketLocation",),
                resources=(bucket_arn,),
                conditions=dict(base),
                explanations=explain(everything),
            )
        )

    if kms_key:
        statements.append(_kms_statement(bucket, kms_key, all_intents, multipart_write, ctx,
                                         include_conditions, everything))  # fmt: skip
    return statements


def _kms_statement(
    bucket: str,
    kms_key: str,
    intents: set[str],
    multipart_write: bool,
    ctx: ArnContext,
    include_conditions: bool,
    explanations: list[Explanation],
) -> Statement:
    actions: set[str] = set()
    if "read" in intents:
        actions.add("kms:Decrypt")
    if "write" in intents:
        actions.add("kms:GenerateDataKey")
        if multipart_write:
            # Uploading parts of an SSE-KMS multipart upload decrypts the data key.
            actions.add("kms:Decrypt")
    conditions: Conditions = {}
    if include_conditions and ctx.region != "*":
        conditions = {"StringEquals": {"kms:ViaService": [f"s3.{ctx.region}.amazonaws.com"]}}
    confidence = min((e.confidence for e in explanations), key=lambda c: c.rank)
    return Statement(
        actions=tuple(sorted(actions)),
        resources=(kms_key_arn(kms_key, ctx),),
        conditions=conditions,
        explanations=(
            Explanation(
                reason=f"Bucket {bucket} is encrypted with SSE-KMS: object access needs the key",
                source=explanations[0].source,
                confidence=confidence,
            ),
        ),
    )
