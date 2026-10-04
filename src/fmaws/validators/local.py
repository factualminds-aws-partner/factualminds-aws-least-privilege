"""Offline IAM policy validation. No AWS calls."""

import json
import re
from pathlib import Path
from typing import Any

from fmaws.models.finding import Finding, Severity
from fmaws.policy import catalog
from fmaws.policy.arns import PROBE, iam_match

MAX_POLICY_BYTES = 1_000_000
MANAGED_POLICY_LIMIT = 6144  # characters, whitespace excluded

_IAM = "https://docs.aws.amazon.com/IAM/latest/UserGuide"
_GRAMMAR = f"{_IAM}/reference_policies_grammar.html"
_LEAST = f"{_IAM}/best-practices.html#grant-least-privilege"

# All patterns are applied with fullmatch: "$" would accept a trailing newline.
# IAM matches action names case-insensitively, so every comparison below is done in lowercase.
_ACTION_RE = re.compile(r"\*+|(?:[A-Za-z0-9-]+|\*):[A-Za-z0-9*?]+")
_ARN_RE = re.compile(
    r"arn:(aws|aws-cn|aws-us-gov|\*):[a-z0-9*?-]+:[a-z0-9*?-]*:(\d{12}|aws|[\d*?]*[*?][\d*?]*)?:[^\s]+"
)
_ALL_ARN_RE = re.compile(r"arn:[^:]*:\*+:\*+:\*+:\*+")
_VARIABLE_RE = re.compile(r"\$\{[^}]*\}")
_SID_RE = re.compile(r"[A-Za-z0-9]*")
# A resource part that matches two unrelated names matches everything in the service.
_PROBES = ("a7/fmaws-probe", "zq/k/fmaws:probe-b")
_TYPE_PREFIX_RE = re.compile(r"[A-Za-z-]+[:/]")
_TOP_LEVEL_KEYS = {"Version", "Id", "Statement"}
_STATEMENT_KEYS = {
    "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource",
    "NotResource", "Condition",
}  # fmt: skip
# Granting any of these on arbitrary principals lets the holder raise its own privileges.
_ESCALATION_ACTIONS = (
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutGroupPolicy",
    "iam:PutRolePolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile", "iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup",
    "sts:AssumeRole",
)  # fmt: skip
_IAM_KINDS = ("user", "role", "group", "policy")
# Operators under which iam:PassedToService really narrows the services a role can be passed to.
_RESTRICTING_OPERATORS = {"stringequals", "stringlike", "stringequalsignorecase"}
_SENSITIVE_SERVICES = {"iam", "sts", "organizations", "kms"}

# id -> (title, why it matters, remediation, documentation)
_META: dict[str, tuple[str, str, str, str]] = {
    "POLICY_INVALID_JSON": (
        "Policy is not valid JSON",
        "IAM rejects documents that are not valid JSON.",
        "Fix the JSON syntax error and validate again.",
        _GRAMMAR,
    ),
    "POLICY_TOO_LARGE": (
        "Policy file is too large to analyze",
        "IAM policies are limited to a few kilobytes; a file this large is not a policy.",
        "Point fmaws at a single IAM policy document.",
        f"{_IAM}/reference_iam-quotas.html",
    ),
    "POLICY_INVALID_STRUCTURE": (
        "Policy structure is invalid",
        "IAM rejects policies that do not follow the policy grammar.",
        "Correct the element so it follows the IAM policy grammar.",
        _GRAMMAR,
    ),
    "POLICY_VERSION": (
        "Policy does not use Version 2012-10-17",
        "Older policy versions do not support policy variables and newer features.",
        'Set "Version": "2012-10-17".',
        f"{_IAM}/reference_policies_elements_version.html",
    ),
    "POLICY_INVALID_ACTION": (
        "Action is not a valid IAM action name",
        "IAM rejects or silently ignores malformed action names.",
        'Use the "service:Action" form, for example "s3:GetObject".',
        f"{_IAM}/reference_policies_elements_action.html",
    ),
    "POLICY_INVALID_ARN": (
        "Resource is not a valid ARN",
        "A malformed ARN never matches, so the statement grants nothing or is rejected.",
        'Use a full ARN ("arn:partition:service:region:account:resource") or "*".',
        f"{_IAM}/reference_policies_elements_resource.html",
    ),
    "POLICY_DUPLICATE_SID": (
        "Statement IDs are not unique",
        "IAM requires Sid values to be unique within a policy.",
        "Give each statement a distinct Sid.",
        f"{_IAM}/reference_policies_elements_sid.html",
    ),
    "POLICY_FULL_ADMIN": (
        "Statement grants every action on every resource",
        "This is administrator access: any compromise of the principal compromises the account.",
        "Replace with explicit actions on specific resources.",
        _LEAST,
    ),
    "POLICY_ACTION_WILDCARD": (
        'Statement allows Action "*"',
        "Every current and future action of every service is allowed on the listed resources.",
        "List the specific actions the workload calls.",
        _LEAST,
    ),
    "POLICY_SERVICE_WILDCARD": (
        "Statement allows every action of a service",
        "Service wildcards include destructive and administrative actions and grow as AWS "
        "adds new ones.",
        "List the specific actions the workload calls.",
        _LEAST,
    ),
    "POLICY_PARTIAL_WILDCARD": (
        "Action uses a partial wildcard",
        "Partial wildcards match more actions than intended as AWS adds new ones.",
        "Prefer explicit action names.",
        _LEAST,
    ),
    "POLICY_NOT_ACTION_ALLOW": (
        "Allow statement uses NotAction",
        "Allow with NotAction grants everything except the listed actions, including future ones.",
        "Use Action with an explicit list.",
        f"{_IAM}/reference_policies_elements_notaction.html",
    ),
    "POLICY_NOT_RESOURCE_ALLOW": (
        "Allow statement uses NotResource",
        "Allow with NotResource grants access to every resource except the listed ones.",
        "Use Resource with an explicit list.",
        f"{_IAM}/reference_policies_elements_notresource.html",
    ),
    "POLICY_PASSROLE_BROAD": (
        "iam:PassRole is allowed on every role",
        "Passing any role to a service is a well-known privilege escalation path.",
        "Restrict Resource to the specific role ARNs and add an iam:PassedToService condition.",
        f"{_IAM}/id_roles_use_passrole.html",
    ),
    "POLICY_PRIVILEGE_ESCALATION": (
        "Statement allows IAM privilege escalation on any principal",
        "The holder can grant itself more permissions, for example by attaching a policy or "
        "assuming any role.",
        "Remove the action or restrict Resource to the specific users, roles or policies.",
        f"{_IAM}/best-practices.html#grant-least-privilege",
    ),
    "POLICY_RESOURCE_WILDCARD": (
        'Actions that support resource-level permissions are allowed on Resource "*"',
        "The actions apply to every resource of that type in the account.",
        "Scope Resource to the specific ARNs the workload uses.",
        _LEAST,
    ),
    "POLICY_RESOURCE_WILDCARD_UNKNOWN": (
        'Resource "*" on actions fmaws cannot classify',
        "If the actions support resource-level permissions, the statement is broader than needed.",
        "Check the Service Authorization Reference and scope Resource where supported.",
        "https://docs.aws.amazon.com/service-authorization/latest/reference/",
    ),
    "POLICY_BROAD_RESOURCE": (
        "Resource matches every resource of a service",
        "The statement applies to all current and future resources of that service.",
        "Name the specific resources.",
        _LEAST,
    ),
    "POLICY_ACCOUNT_WILDCARD": (
        "Resource ARN has a wildcard account ID",
        "The ARN also matches identically named resources in other accounts.",
        "Set aws.account_id in fmaws.yaml (or use --profile) so ARNs carry the account ID.",
        f"{_IAM}/reference_policies_elements_resource.html",
    ),
    "POLICY_PUBLIC_PRINCIPAL": (
        "Statement allows any principal",
        "Unless a condition restricts the caller, anyone on the internet can use the actions.",
        "Name specific principals, or verify that the condition restricts who can call.",
        f"{_IAM}/reference_policies_elements_principal.html",
    ),
    "POLICY_SIZE": (
        "Policy exceeds the managed policy size limit",
        "IAM rejects managed policies larger than 6,144 characters.",
        "Split the policy into several managed policies.",
        f"{_IAM}/reference_iam-quotas.html",
    ),
}


def _finding(
    finding_id: str,
    severity: Severity,
    problem: str,
    resource: str = "",
    evidence: dict[str, Any] | None = None,
) -> Finding:
    title, why, fix, url = _META[finding_id]
    return Finding(
        id=finding_id,
        severity=severity,
        category="policy",
        service="iam",
        resource=resource,
        title=title,
        problem=problem,
        why_it_matters=why,
        evidence=evidence or {},
        recommendation=fix,
        remediation=fix,
        documentation_url=url,
    )


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON parsers disagree on duplicate keys, so a policy that has them is rejected."""
    result = dict(pairs)
    if len(result) != len(pairs):
        keys = [key for key, _ in pairs]
        duplicate = min(key for key in result if keys.count(key) > 1)
        raise ValueError(f"duplicate key {duplicate!r}")
    return result


def _reject_constant(name: str) -> Any:
    """NaN and Infinity are accepted by Python's parser but are not JSON."""
    raise ValueError(f"{name} is not valid JSON")


def load_policy_file(path: Path) -> tuple[Any, list[Finding]]:
    """Parse a policy file. Problems are returned as findings, never raised."""
    if path.stat().st_size > MAX_POLICY_BYTES:
        return None, [
            _finding("POLICY_TOO_LARGE", Severity.HIGH, f"{path.name} is larger than 1 MB.")
        ]
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(
            text, object_pairs_hook=no_duplicate_keys, parse_constant=_reject_constant
        ), []
    except (ValueError, RecursionError) as exc:
        return None, [_finding("POLICY_INVALID_JSON", Severity.HIGH, f"{path.name}: {exc}")]


def validate_policy_document(
    document: Any, wildcard_severity: Severity = Severity.MEDIUM
) -> list[Finding]:
    def invalid(problem: str, where: str = "") -> Finding:
        return _finding("POLICY_INVALID_STRUCTURE", Severity.HIGH, problem, where)

    if not isinstance(document, dict) or "Statement" not in document:
        return [invalid('The policy must be a JSON object with a "Statement" element.')]

    findings: list[Finding] = []
    for key in sorted(set(document) - _TOP_LEVEL_KEYS):
        findings.append(
            invalid(f"Unknown policy element {key!r}. Element names are case-sensitive.")
        )
    if document["Statement"] in ([], {}):
        findings.append(invalid("Statement is empty: the policy grants nothing."))
    if document.get("Version") != "2012-10-17":
        findings.append(
            _finding("POLICY_VERSION", Severity.MEDIUM, f"Version is {document.get('Version')!r}.")
        )

    star_only = catalog.star_actions()
    scoped = catalog.scoped_actions()
    seen_sids: set[str] = set()
    for index, statement in enumerate(as_list(document["Statement"])):
        where = f"Statement[{index}]"
        if not isinstance(statement, dict):
            findings.append(invalid("Each statement must be a JSON object.", where))
            continue
        unknown_keys = sorted(set(statement) - _STATEMENT_KEYS)
        if unknown_keys:
            # IAM rejects these. Ignoring them would hide, for example, a misspelled Condition.
            findings.append(
                invalid(
                    f"Unknown statement element {unknown_keys[0]!r}. "
                    "Element names are case-sensitive.",
                    where,
                )
            )
        sid = statement.get("Sid", "")
        if sid:
            where = f"{where} ({sid})" if isinstance(sid, str) else where
            if not isinstance(sid, str) or not _SID_RE.fullmatch(sid):
                findings.append(invalid("Sid must contain only letters and digits.", where))
            elif sid in seen_sids:
                findings.append(
                    _finding("POLICY_DUPLICATE_SID", Severity.HIGH, f"Sid {sid} repeats.", where)
                )
            seen_sids.add(str(sid))
        effect = statement.get("Effect")
        if effect not in ("Allow", "Deny"):
            findings.append(invalid(f'Effect must be "Allow" or "Deny", found {effect!r}.', where))
            continue
        if ("Action" in statement) == ("NotAction" in statement):
            findings.append(invalid("A statement needs exactly one of Action or NotAction.", where))
            continue
        if "Resource" in statement and "NotResource" in statement:
            findings.append(
                invalid("A statement cannot have both Resource and NotResource.", where)
            )
            continue
        if "Principal" in statement and "NotPrincipal" in statement:
            findings.append(
                invalid("A statement cannot have both Principal and NotPrincipal.", where)
            )
            continue
        has_principal = "Principal" in statement or "NotPrincipal" in statement
        if "Resource" not in statement and "NotResource" not in statement and not has_principal:
            findings.append(invalid("A statement needs Resource or NotResource.", where))
            continue
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            findings.append(invalid("Condition must be a JSON object.", where))

        actions = as_list(statement.get("Action", statement.get("NotAction")))
        resources = as_list(statement.get("Resource", statement.get("NotResource", [])))
        bad_actions = [a for a in actions if not isinstance(a, str) or not _ACTION_RE.fullmatch(a)]
        for action in bad_actions:
            findings.append(
                _finding(
                    "POLICY_INVALID_ACTION", Severity.HIGH, f"Invalid action {action!r}.", where
                )
            )
        bad_resources = [r for r in resources if not isinstance(r, str) or not _valid_resource(r)]
        for resource in bad_resources:
            findings.append(
                _finding(
                    "POLICY_INVALID_ARN", Severity.HIGH, f"Invalid resource {resource!r}.", where
                )
            )
        if effect != "Allow":
            continue
        # Invalid elements are reported above; the valid ones are still checked for breadth.
        good_actions = [a for a in actions if a not in bad_actions]
        good_resources = [r for r in resources if r not in bad_resources]
        findings.extend(
            _breadth(
                statement, good_actions, good_resources, where, wildcard_severity, star_only, scoped
            )
        )

    # IAM counts characters outside of JSON whitespace; whitespace inside strings counts.
    size = len(json.dumps(document, separators=(",", ":"), ensure_ascii=False))
    if size > MANAGED_POLICY_LIMIT:
        findings.append(
            _finding(
                "POLICY_SIZE",
                Severity.MEDIUM,
                f"Policy is {size} characters.",
                evidence={"size": size, "limit": MANAGED_POLICY_LIMIT},
            )
        )
    return findings


def _is_any(value: str) -> bool:
    return re.fullmatch(r"\*+", value) is not None


def _valid_resource(resource: str) -> bool:
    """``*`` or an ARN. Policy variables are allowed inside an ARN, never instead of one."""
    return _is_any(resource) or _ARN_RE.fullmatch(_VARIABLE_RE.sub("x", resource)) is not None


def _every_action(action: str) -> bool:
    """``*`` and its equivalent spellings (``**``, ``*:*``)."""
    return _is_any(action.replace(":", "*"))


def _every_resource(resource: str) -> bool:
    """``*`` and its equivalent spellings (``**``, ``arn:aws:*:*:*:*``)."""
    return _is_any(resource) or _ALL_ARN_RE.fullmatch(resource) is not None


def _every_iam(resource: str, kinds: tuple[str, ...]) -> bool:
    """True when the ARN matches arbitrary IAM users/roles/groups/policies, whatever the account."""
    parts = resource.split(":", 5)
    return (
        len(parts) == 6
        and iam_match(parts[2], "iam")
        and any(iam_match(parts[5], f"{kind}/{PROBE}") for kind in kinds)
    )


def condition_values(condition: dict[str, Any]) -> list[tuple[str, str, list[Any]]]:
    return [
        (operator, str(key), as_list(values))
        for operator, keys in condition.items()
        if isinstance(keys, dict)
        for key, values in keys.items()
    ]


def trivial_condition(condition: dict[str, Any]) -> bool:
    """A condition that is always true: wildcard-only values under a *Like operator."""
    entries = condition_values(condition)
    return bool(entries) and all(
        operator.lower().removeprefix("foranyvalue:").removesuffix("ifexists")
        in ("stringlike", "arnlike")
        and values
        and all(isinstance(v, str) and _is_any(v) for v in values)
        for operator, _, values in entries
    )


def _pins_kms_alias(condition: dict[str, Any]) -> bool:
    return any(
        operator.lower() in ("foranyvalue:stringequals", "stringequals")
        and key.lower() == "kms:resourcealiases"
        and values
        and all(isinstance(v, str) and "*" not in v and "?" not in v for v in values)
        for operator, key, values in condition_values(condition)
    )


def _any_principal(principal: Any) -> bool:
    """``"*"`` in any of its forms: bare, ``{"AWS": "*"}`` or inside a list."""
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    return any("*" in as_list(value) for value in principal.values())


def _restricts_passed_service(condition: dict[str, Any]) -> bool:
    """True only when iam:PassedToService is pinned to specific services.

    A negated operator, an ``IfExists`` variant or a wildcard value does not narrow anything.
    """
    for operator, keys in condition.items():
        if operator.lower() not in _RESTRICTING_OPERATORS or not isinstance(keys, dict):
            continue
        for key, values in keys.items():
            if key.lower() != "iam:passedtoservice":
                continue
            services = as_list(values)
            if services and all(isinstance(v, str) and "*" not in v and v for v in services):
                return True
    return False


def action_allows(pattern: str, action: str) -> bool:
    return iam_match(pattern.lower(), action.lower())


def _breadth(
    statement: dict[str, Any],
    actions: list[str],
    resources: list[str],
    where: str,
    wildcard_severity: Severity,
    star_only: dict[str, str],
    scoped: set[str],
) -> list[Finding]:
    """Checks for Allow statements that grant more than a workload plausibly needs."""
    condition = statement.get("Condition")
    condition = condition if isinstance(condition, dict) else {}
    # Only a well-formed condition that can evaluate to false narrows a statement.
    conditioned = bool(condition) and not trivial_condition(condition)

    findings = _principal_findings(statement, conditioned, where)
    if "NotResource" in statement:
        # Everything except the listed resources is in scope: treat it as every resource,
        # unless the exclusion itself covers everything. The listed ARNs are exclusions, so
        # their own breadth says nothing about what is granted.
        all_resources = not any(_every_resource(r) for r in resources)
        any_role = any_principal = all_resources
        resources = []
        findings.append(
            _finding(
                "POLICY_NOT_RESOURCE_ALLOW",
                Severity.MEDIUM,
                "Every resource except the listed ones is in scope.",
                where,
            )
        )
    else:
        all_resources = any(_every_resource(r) for r in resources)
        any_role = all_resources or any(_every_iam(r, ("role",)) for r in resources)
        any_principal = all_resources or any(_every_iam(r, _IAM_KINDS) for r in resources)

    if "NotAction" in statement:
        findings.append(
            _finding(
                "POLICY_NOT_ACTION_ALLOW",
                Severity.HIGH,
                "Everything except the listed actions is allowed.",
                where,
            )
        )
        return findings
    if any(_every_action(a) for a in actions):
        if all_resources and not conditioned:
            findings.append(
                _finding(
                    "POLICY_FULL_ADMIN",
                    Severity.CRITICAL,
                    "Every action is allowed on every resource.",
                    where,
                )
            )
        else:
            findings.append(
                _finding("POLICY_ACTION_WILDCARD", Severity.HIGH, "Every action is allowed.", where)
            )
        return findings

    findings += _wildcard_action_findings(actions, all_resources, wildcard_severity, where)
    findings += _iam_findings(actions, any_role, any_principal, condition, conditioned, where)
    if all_resources:
        findings += _star_resource_findings(actions, star_only, scoped, where)
    findings += _arn_findings(resources, condition, conditioned, where)
    return findings


def _principal_findings(statement: dict[str, Any], conditioned: bool, where: str) -> list[Finding]:
    if "NotPrincipal" in statement:
        problem = "Allow with NotPrincipal grants access to everyone except the listed principals."
        return [_finding("POLICY_PUBLIC_PRINCIPAL", Severity.HIGH, problem, where)]
    if not _any_principal(statement.get("Principal")):
        return []
    # fmaws cannot prove that an arbitrary condition restricts the caller, so a conditioned
    # wildcard principal is still reported, at a lower severity.
    if conditioned:
        problem, severity = 'Principal is "*", limited only by its condition.', Severity.MEDIUM
    else:
        problem, severity = 'Principal is "*" with no effective condition.', Severity.CRITICAL
    return [_finding("POLICY_PUBLIC_PRINCIPAL", severity, problem, where)]


def _wildcard_action_findings(
    actions: list[str], all_resources: bool, wildcard_severity: Severity, where: str
) -> list[Finding]:
    findings: list[Finding] = []
    for action in actions:
        service, name = action.lower().split(":", 1)
        sensitive = service in _SENSITIVE_SERVICES or "*" in service
        if _is_any(name):
            # Every action of a service on every resource is service-level administrator access.
            rule = "POLICY_SERVICE_WILDCARD"
            severity = Severity.HIGH if sensitive or all_resources else wildcard_severity
        elif "*" in name or "?" in name:
            rule = "POLICY_PARTIAL_WILDCARD"
            if sensitive:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM if all_resources else Severity.LOW
        else:
            continue
        findings.append(
            _finding(rule, severity, f"{action} is allowed.", where, {"action": action})
        )
    return findings


def _iam_findings(
    actions: list[str],
    any_role: bool,
    any_principal: bool,
    condition: dict[str, Any],
    conditioned: bool,
    where: str,
) -> list[Finding]:
    """PassRole on every role, and actions that let the holder raise its own privileges."""
    findings: list[Finding] = []
    passes_role = any(action_allows(a, "iam:PassRole") for a in actions)
    if passes_role and any_role and not _restricts_passed_service(condition):
        findings.append(
            _finding(
                "POLICY_PASSROLE_BROAD",
                Severity.HIGH,
                "iam:PassRole is allowed on every role.",
                where,
            )
        )
    escalations = sorted(
        target for target in _ESCALATION_ACTIONS if any(action_allows(a, target) for a in actions)
    )
    if escalations and any_principal:
        # A condition fmaws cannot evaluate lowers the severity. It never hides the finding.
        suffix = ", limited only by its condition." if conditioned else "."
        findings.append(
            _finding(
                "POLICY_PRIVILEGE_ESCALATION",
                Severity.MEDIUM if conditioned else Severity.HIGH,
                f"{', '.join(escalations)} allowed on arbitrary IAM principals{suffix}",
                where,
                {"actions": escalations},
            )
        )
    return findings


def _star_resource_findings(
    actions: list[str], star_only: dict[str, str], scoped: set[str], where: str
) -> list[Finding]:
    """Explicit actions on every resource: scopable ones, and ones fmaws cannot classify."""
    scoped_lower = {a.lower() for a in scoped}
    # Reported by their own rules, or legitimately unscoped.
    accounted = {a.lower() for a in (*star_only, *_ESCALATION_ACTIONS, "iam:PassRole")}
    explicit = [a for a in actions if "*" not in a and "?" not in a]
    scopable = sorted(a for a in explicit if a.lower() in scoped_lower)
    unknown = sorted(a for a in explicit if a.lower() not in scoped_lower | accounted)
    findings: list[Finding] = []
    if scopable:
        findings.append(
            _finding(
                "POLICY_RESOURCE_WILDCARD",
                Severity.MEDIUM,
                f"{', '.join(scopable)} allowed on every resource.",
                where,
                {"actions": scopable},
            )
        )
    if unknown:
        findings.append(
            _finding(
                "POLICY_RESOURCE_WILDCARD_UNKNOWN",
                Severity.LOW,
                f'{", ".join(unknown)} allowed on Resource "*".',
                where,
                {"actions": unknown},
            )
        )
    return findings


def _type_wide(name: str) -> bool:
    """Matches arbitrary resources of one type: "table/*", "secret:*", "log-group:*:*"."""
    prefix = _TYPE_PREFIX_RE.match(name)
    if prefix is None or "*" not in name:
        return False
    samples = (f"{prefix[0]}{PROBE}", f"{prefix[0]}{PROBE}:{PROBE}")
    return any(iam_match(name, sample) for sample in samples)


def _arn_findings(
    resources: list[str], condition: dict[str, Any], conditioned: bool, where: str
) -> list[Finding]:
    """Resource ARNs that match every resource of a service or type, or any account."""
    findings: list[Finding] = []
    for resource in resources:
        parts = resource.split(":", 5)
        if _every_resource(resource) or len(parts) != 6:
            continue
        service, account, name = parts[2], parts[4], parts[5]
        # "bucket/*" has the same shape as a type-wide ARN but is one bucket.
        if _type_wide(name) and service != "s3":
            if service == "kms" and _pins_kms_alias(condition):
                continue  # the documented way to authorize a key by alias
            suffix = ", limited only by its condition." if conditioned else "."
            findings.append(
                _finding(
                    "POLICY_BROAD_RESOURCE",
                    Severity.LOW if conditioned else Severity.MEDIUM,
                    f"{resource} matches every {service} resource of that type{suffix}",
                    where,
                )
            )
        elif all(iam_match(name, probe) for probe in _PROBES):
            # A wildcard service ("arn:aws:*:*::*") reaches far beyond one service.
            findings.append(
                _finding(
                    "POLICY_BROAD_RESOURCE",
                    Severity.HIGH if "*" in service else Severity.MEDIUM,
                    f"{resource} matches every {service} resource.",
                    where,
                )
            )
        elif "*" in account or "?" in account:
            findings.append(
                _finding(
                    "POLICY_ACCOUNT_WILDCARD",
                    Severity.LOW,
                    f"{resource} does not pin the account.",
                    where,
                )
            )
    return findings
