"""Turn resource requirements into IAM statements through the service catalog."""

import re
from itertools import groupby

from fmaws.errors import ConfigError
from fmaws.models.policy import Conditions, Explanation, PolicyDocument, Statement
from fmaws.models.requirement import ResourceRequirement
from fmaws.policy import catalog, s3
from fmaws.policy.arns import ArnContext, build_arn, kms_key_arn, parse_arn, validate_name
from fmaws.policy.optimizer import optimize

# Cross-region inference profile IDs are a geography prefix followed by the model ID.
_INFERENCE_PROFILE_RE = re.compile(r"^(us|eu|apac|global|us-gov)\.(.+)$")


def _resources(req: ResourceRequirement, ctx: ArnContext) -> tuple[list[str], Conditions, str]:
    """Base resources, conditions and an explanation note for one non-S3 requirement."""
    definition = catalog.get(req.service)
    name = req.resource
    if name.startswith("arn:"):
        if parse_arn(definition, name) is None:
            raise ConfigError(f"Malformed {definition.title} ARN '{name}'.")
        return [name], {}, ""
    validate_name(name, definition.title)

    if req.service == "kms" and name.startswith("alias/"):
        return (
            [build_arn(definition, "*", ctx)],
            {"ForAnyValue:StringEquals": {"kms:ResourceAliases": [name]}},
            " KMS authorizes keys, not aliases: scoped with kms:ResourceAliases.",
        )

    profile = _INFERENCE_PROFILE_RE.match(name) if req.service == "bedrock" else None
    if profile:
        return (
            [
                f"arn:{ctx.partition}:bedrock:{ctx.region}:{ctx.account}:inference-profile/{name}",
                f"arn:{ctx.partition}:bedrock:*::foundation-model/{profile.group(2)}",
            ],
            {},
            " Cross-region inference profile: Bedrock also authorizes the foundation model in "
            "every destination region.",
        )
    return [build_arn(definition, name, ctx)], {}, ""


def _generic(
    req: ResourceRequirement, ctx: ArnContext, include_conditions: bool
) -> list[Statement]:
    definition = catalog.get(req.service)
    resources, conditions, note = _resources(req, ctx)
    scoped: set[str] = set()
    starred: set[str] = set()
    for intent in req.intents:
        for action in definition.actions_for(intent):
            (starred if action in definition.star_actions else scoped).add(action)
        if intent in definition.extra_resources and not conditions:
            base = resources[0].removesuffix(":*")
            resources = resources + [base + suffix for suffix in definition.extra_resources[intent]]

    def explanation(reason: str) -> tuple[Explanation, ...]:
        return (Explanation(reason=reason, source=str(req.source), confidence=req.confidence),)

    target = f"{definition.title} {req.resource}"
    statements: list[Statement] = []
    if scoped:
        statements.append(
            Statement(
                actions=tuple(sorted(scoped)),
                resources=tuple(resources),
                conditions=conditions,
                explanations=explanation(
                    f"{req.reason}: {', '.join(sorted(req.intents))} on {target}.{note}"
                ),
            )
        )
    for action in sorted(starred):
        statements.append(
            Statement(
                actions=(action,),
                resources=("*",),
                explanations=explanation(
                    f'{req.reason}: {action} requires Resource "*". '
                    f"{definition.star_actions[action]}"
                ),
            )
        )

    kms_key = req.options.get("kms_key")
    if kms_key:
        kms_actions = {a for i in req.intents for a in definition.kms_actions.get(i, ())}
        if kms_actions:
            via: Conditions = {}
            if include_conditions and ctx.region != "*":
                service_host = f"{definition.kms_via_service}.{ctx.region}.amazonaws.com"
                via = {"StringEquals": {"kms:ViaService": [service_host]}}
            statements.append(
                Statement(
                    actions=tuple(sorted(kms_actions)),
                    resources=(kms_key_arn(str(kms_key), ctx),),
                    conditions=via,
                    explanations=explanation(
                        f"{target} is encrypted with a customer managed KMS key"
                    ),
                )
            )
    return statements


def generate_statements(
    requirements: list[ResourceRequirement], ctx: ArnContext, include_conditions: bool = True
) -> list[Statement]:
    statements: list[Statement] = []
    ordered = sorted(requirements, key=lambda r: (r.service, r.resource, str(r.source)))
    for (service, resource), group in groupby(ordered, key=lambda r: (r.service, r.resource)):
        reqs = list(group)
        if service == "s3":
            statements.extend(s3.build_bucket(resource, reqs, ctx, include_conditions))
        else:
            for req in reqs:
                statements.extend(_generic(req, ctx, include_conditions))
    return statements


def generate_policy(
    requirements: list[ResourceRequirement], ctx: ArnContext, include_conditions: bool = True
) -> PolicyDocument:
    """Deterministic candidate policy for the given requirements."""
    statements = generate_statements(requirements, ctx, include_conditions)
    return PolicyDocument(statements=tuple(optimize(statements)))
