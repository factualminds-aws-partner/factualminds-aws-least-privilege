"""Combine declared and discovered requirements into one deterministic list."""

from collections import Counter
from itertools import groupby

from fmaws.models.requirement import ResourceRequirement
from fmaws.policy import catalog
from fmaws.policy.arns import parse_arn


def _key(req: ResourceRequirement) -> tuple[str, str]:
    """Service and resource name, so an ARN and a bare name of the same resource collide."""
    if req.service != "s3" and req.resource.startswith("arn:"):
        parsed = parse_arn(catalog.get(req.service), req.resource)
        if parsed:
            return req.service, parsed["name"]
    return req.service, req.resource


def merge_requirements(
    declared: list[ResourceRequirement], discovered: list[ResourceRequirement]
) -> list[ResourceRequirement]:
    """Declared resources win. Discovered evidence for the same resource is folded together."""
    declared_keys = {_key(r) for r in declared}
    remaining = sorted(
        (r for r in discovered if _key(r) not in declared_keys),
        key=lambda r: (_key(r), -r.confidence.rank, str(r.source.file), r.source.line or 0),
    )
    merged: list[ResourceRequirement] = []
    for _, group in groupby(remaining, key=_key):
        evidence = list(group)
        best = evidence[0]
        confirmed = [r for r in evidence if r.intent_confirmed]
        intents = sorted({i for r in (confirmed or evidence) for i in r.intents})
        # Prefer a full ARN when one was seen: it pins account and region exactly.
        resource = next(
            (r.resource for r in evidence if r.resource.startswith("arn:")), best.resource
        )
        merged.append(
            best.model_copy(
                update={
                    "resource": resource,
                    "intents": tuple(intents),
                    "intent_confirmed": bool(confirmed),
                }
            )
        )
    return [*declared, *merged]


def single(values: list[str]) -> str | None:
    """The value, when discovery saw exactly one distinct value."""
    counts = Counter(values)
    return next(iter(counts)) if len(counts) == 1 else None
