"""IAM analyzers: root user, credentials, permissions and role trust.

Two data sets cover everything: the credential report and GetAccountAuthorizationDetails.
Each is fetched once per run and shared.
"""

import csv
import io
import time
from datetime import datetime
from typing import Any

from fmaws.audit import policies
from fmaws.audit.base import UNREADABLE, AuditContext, register
from fmaws.audit.findings import RULES, make
from fmaws.errors import AwsAuthError
from fmaws.models.finding import Finding, Severity
from fmaws.models.requirement import Confidence
from fmaws.policy.arns import PROBE, iam_match
from fmaws.validators.local import validate_policy_document

ROOT = "<root_account>"
_REPORT_ATTEMPTS = 15
_SERVICE_LINKED = "/aws-service-role/"
_SSO_MANAGED = "/aws-reserved/"

# Local validator finding -> audit rule.
_BREADTH = {
    "POLICY_FULL_ADMIN": "IAM_POLICY_ADMIN",
    "POLICY_ACTION_WILDCARD": "IAM_POLICY_ACTION_WILDCARD",
    "POLICY_NOT_ACTION_ALLOW": "IAM_POLICY_NOT_ACTION",
    "POLICY_SERVICE_WILDCARD": "IAM_POLICY_SERVICE_WILDCARD",
    "POLICY_PASSROLE_BROAD": "IAM_POLICY_PASSROLE",
    "POLICY_PRIVILEGE_ESCALATION": "IAM_POLICY_PRIVILEGE_ESCALATION",
    "POLICY_RESOURCE_WILDCARD": "IAM_POLICY_RESOURCE_WILDCARD",
}
_DYNAMODB_DATA = (
    "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PutItem",
    "dynamodb:UpdateItem", "dynamodb:DeleteItem",
)  # fmt: skip


def credential_report(ctx: AuditContext) -> list[dict[str, str]]:
    def fetch() -> list[dict[str, str]]:
        for _ in range(_REPORT_ATTEMPTS):
            if ctx.call("iam", "generate_credential_report").get("State") == "COMPLETE":
                break
            time.sleep(2)
        else:
            raise TimeoutError("IAM did not finish the credential report in time")
        content = ctx.call("iam", "get_credential_report")["Content"]
        text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
        return list(csv.DictReader(io.StringIO(text)))

    rows: list[dict[str, str]] = ctx.cached("iam.credential_report", fetch)
    return rows


def authorization_details(ctx: AuditContext) -> dict[str, list[dict[str, Any]]]:
    def fetch() -> dict[str, list[dict[str, Any]]]:
        pages = ctx.all_pages(
            "iam",
            "get_account_authorization_details",
            Filter=["User", "Role", "Group", "LocalManagedPolicy"],
        )
        keys = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
        return {key: [item for page in pages for item in page.get(key, [])] for key in keys}

    details: dict[str, list[dict[str, Any]]] = ctx.cached("iam.authorization_details", fetch)
    return details


def _when(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:  # "N/A", "no_information", "not_supported"
        return None


class IamRoot:
    name = "iam_root"
    regional = False

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        summary = ctx.call("iam", "get_account_summary")["SummaryMap"]
        resource = f"arn:{ctx.partition}:iam::{ctx.account}:root"
        findings: list[Finding] = []
        root: dict[str, str] = {}
        try:
            root = next((r for r in credential_report(ctx) if r.get("user") == ROOT), {})
        except AwsAuthError:
            raise
        except Exception:  # noqa: BLE001  the report is optional here; iam_credentials reports it
            ctx.gap("iam:GetCredentialReport")

        # Member accounts under centralized root access have no root password at all.
        no_root_password = root.get("password_enabled") == "false"
        if not summary.get("AccountMFAEnabled") and not no_root_password:
            findings.append(
                make("IAM_ROOT_MFA_DISABLED", resource, "The root user has no MFA device.")
            )
        if summary.get("AccountAccessKeysPresent"):
            findings.append(
                make("IAM_ROOT_ACCESS_KEYS", resource, "The root user has active access keys.")
            )
        used = [
            _when(root.get(column))
            for column in (
                "password_last_used",
                "access_key_1_last_used_date",
                "access_key_2_last_used_date",
            )
        ]
        recent = [d for d in (ctx.days_since(u) for u in used) if d is not None and d <= 30]
        if recent:
            findings.append(
                make(
                    "IAM_ROOT_RECENT_USE",
                    resource,
                    f"Root credentials were last used {min(recent)} day(s) ago.",
                    evidence={"days_since_last_use": min(recent)},
                    confidence=Confidence.MEDIUM,
                )
            )
        return findings


class IamCredentials:
    name = "iam_credentials"
    regional = False

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        max_age = ctx.config.audit.max_access_key_age_days
        unused = ctx.config.audit.unused_days
        findings: list[Finding] = []
        for row in credential_report(ctx):
            if row.get("user") == ROOT:
                continue
            arn = row.get("arn", row.get("user", ""))
            console = row.get("password_enabled") == "true"
            if console and row.get("mfa_active") != "true":
                findings.append(
                    make("IAM_USER_NO_MFA", arn, "The user can sign in to the console without MFA.")
                )
            key_recently_used = False
            for number in ("1", "2"):
                if row.get(f"access_key_{number}_active") != "true":
                    continue
                age = ctx.days_since(_when(row.get(f"access_key_{number}_last_rotated")))
                idle = ctx.days_since(_when(row.get(f"access_key_{number}_last_used_date")))
                evidence = {"key": number, "age_days": age, "days_since_last_use": idle}
                never = idle is None
                if (never or (idle is not None and idle > unused)) and (age or 0) > unused:
                    last = "has never been used" if never else f"was last used {idle} days ago"
                    findings.append(
                        make(
                            "IAM_ACCESS_KEY_UNUSED",
                            arn,
                            f"Access key {number} is active, {age} days old and {last}.",
                            evidence=evidence,
                        )
                    )
                    continue
                key_recently_used = True
                if age is not None and age > max_age:
                    findings.append(
                        make(
                            "IAM_ACCESS_KEY_OLD",
                            arn,
                            f"Access key {number} is {age} days old (limit {max_age}). "
                            "Workloads should use roles instead of long-lived keys.",
                            evidence=evidence,
                        )
                    )
            if console and not key_recently_used:
                last_login = ctx.days_since(_when(row.get("password_last_used")))
                created = ctx.days_since(_when(row.get("user_creation_time"))) or 0
                if (last_login is None and created > unused) or (last_login or 0) > unused:
                    seen = "never" if last_login is None else f"{last_login} days ago"
                    findings.append(
                        make(
                            "IAM_USER_INACTIVE",
                            arn,
                            f"Last console sign-in: {seen}.",
                            evidence={"days_since_sign_in": last_login},
                        )
                    )
        return findings


def _reaches_every(statement: dict[str, Any], service: str, name: str) -> bool:
    """Does a resource of the statement match an arbitrary resource of that service and type?

    Region and account are ignored on purpose: every secret of one Region is still every secret.
    """
    for resource in policies.resources(statement):
        parts = resource.split(":", 5)
        if resource == "*" or (
            len(parts) == 6 and iam_match(parts[2], service) and iam_match(parts[5], name)
        ):
            return True
    return False


# rule -> (actions, service, resource name of an arbitrary resource, problem)
_DATA_WILDCARDS = {
    "IAM_SECRETS_WILDCARD_ACCESS": (
        ("secretsmanager:GetSecretValue",),
        "secretsmanager",
        f"secret:{PROBE}",
        "secretsmanager:GetSecretValue is allowed on every secret.",
    ),
    "IAM_DYNAMODB_WILDCARD_ACCESS": (
        _DYNAMODB_DATA,
        "dynamodb",
        f"table/{PROBE}",
        "DynamoDB data actions are allowed on every table.",
    ),
}
_ONE_STEP_LOWER = {Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW}


def policy_findings(
    document: Any, resource: str, attached: bool, ctx: AuditContext
) -> list[Finding]:
    """Breadth findings for one identity policy, one finding per rule."""
    try:
        document = policies.parse(document)
        statements = policies.allow_statements(document)
    except policies.UnreadablePolicy:
        ctx.gap(UNREADABLE)
        return []
    findings: list[Finding] = []
    note = "" if attached else " The policy is not attached to any principal."
    grouped: dict[str, list[Finding]] = {}
    for local in validate_policy_document(document):
        if local.id in _BREADTH:
            grouped.setdefault(_BREADTH[local.id], []).append(local)
    for rule_id, items in sorted(grouped.items()):
        worst = max(items, key=lambda f: f.severity.rank).severity
        severity = min(worst, Severity.HIGH, key=lambda s: s.rank) if attached else Severity.LOW
        problems = sorted({f"{f.resource}: {f.problem}" for f in items})
        statement_labels = sorted({f.resource for f in items})
        findings.append(
            make(
                rule_id,
                resource,
                " ".join(problems) + note,
                severity=severity,
                evidence={"statements": statement_labels},
            )
        )

    # Full admin is already reported above.
    eligible = [s for s in statements if not policies.allows(s, f"{PROBE}:{PROBE}")]
    for rule_id, (actions, service, name, problem) in _DATA_WILDCARDS.items():
        hits = [
            s for s in eligible if policies.allows(s, *actions) and _reaches_every(s, service, name)
        ]
        if not hits:
            continue
        # A condition fmaws cannot evaluate lowers the severity. It never hides the finding.
        conditioned = all(policies.is_conditioned(s) for s in hits)
        default = RULES[rule_id].severity
        if not attached:
            severity = Severity.LOW
        else:
            severity = _ONE_STEP_LOWER[default] if conditioned else default
        limited = " Limited only by a condition fmaws cannot verify." if conditioned else ""
        findings.append(make(rule_id, resource, problem + limited + note, severity=severity))
    return findings


class IamPolicies:
    name = "iam_policies"
    regional = False

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        details = authorization_details(ctx)
        findings: list[Finding] = []
        for policy in details["Policies"]:
            default = next(
                (v for v in policy.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None
            )
            if default:
                attached = policy.get("AttachmentCount", 0) > 0
                findings.extend(
                    policy_findings(default.get("Document"), policy["Arn"], attached, ctx)
                )

        principals = (
            ("user", "UserDetailList", "UserPolicyList"),
            ("group", "GroupDetailList", "GroupPolicyList"),
            ("role", "RoleDetailList", "RolePolicyList"),
        )
        for kind, list_key, inline_key in principals:
            for principal in details[list_key]:
                arn = principal["Arn"]
                path = principal.get("Path", "/")
                if path.startswith(_SERVICE_LINKED):
                    continue
                for inline in principal.get(inline_key, []):
                    target = f"{arn} (inline policy {inline.get('PolicyName')})"
                    findings.extend(
                        policy_findings(inline.get("PolicyDocument"), target, True, ctx)
                    )
                if kind == "user" and principal.get(inline_key):
                    names = sorted(p.get("PolicyName", "") for p in principal[inline_key])
                    findings.append(
                        make(
                            "IAM_USER_INLINE_POLICY", arn, f"Inline policies: {', '.join(names)}."
                        )  # fmt: skip
                    )
                admin = any(
                    str(p.get("PolicyArn", "")).endswith(":policy/AdministratorAccess")
                    for p in principal.get("AttachedManagedPolicies", [])
                )
                if admin and not path.startswith(_SSO_MANAGED):
                    # Long-lived identities with admin are worse than roles that must be assumed.
                    severity = Severity.MEDIUM if kind == "role" else Severity.HIGH
                    findings.append(
                        make(
                            "IAM_ADMIN_ATTACHED",
                            arn,
                            f"AdministratorAccess is attached to this {kind}.",
                            severity=severity,
                        )
                    )
        return findings


class IamRoles:
    name = "iam_roles"
    regional = False

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        trusted = set(ctx.config.audit.trusted_accounts)
        unused_days = ctx.config.audit.unused_days
        findings: list[Finding] = []
        for role in authorization_details(ctx)["RoleDetailList"]:
            arn = role["Arn"]
            path = role.get("Path", "/")
            if path.startswith(_SERVICE_LINKED):
                continue
            external: set[str] = set()
            guarded = True
            for statement in ctx.statements(role.get("AssumeRolePolicyDocument")):
                if policies.is_public(statement) and not policies.is_restricted(statement):
                    conditioned = policies.is_conditioned(statement)
                    findings.append(
                        make(
                            "IAM_ROLE_TRUST_PUBLIC",
                            arn,
                            'The trust policy allows Principal "*"'
                            + (
                                " limited only by a condition fmaws cannot verify."
                                if conditioned
                                else " with no condition."
                            ),
                            severity=Severity.MEDIUM if conditioned else None,
                        )
                    )
                accounts = policies.external_accounts(statement, ctx.account, trusted)
                if accounts:
                    external |= accounts
                    guarded = guarded and (
                        policies.is_restricted(statement)
                        or policies.requires_external_id(statement)
                    )
                oidc = [
                    p for p in policies.federated_principals(statement) if "oidc-provider/" in p
                ]
                if oidc and not policies.pins_subject(statement):
                    findings.append(
                        make(
                            "IAM_ROLE_TRUST_OIDC_UNRESTRICTED",
                            arn,
                            f"Any identity of {oidc[0].split('oidc-provider/')[-1]} can assume "
                            "the role: the trust policy has no condition on the subject claim.",
                        )
                    )
            if external:
                findings.append(
                    make(
                        "IAM_ROLE_TRUST_CROSS_ACCOUNT",
                        arn,
                        f"Trusted external account(s): {', '.join(sorted(external))}."
                        + ("" if guarded else " No sts:ExternalId or organization condition."),
                        severity=Severity.LOW if guarded else None,
                        evidence={"accounts": sorted(external)},
                    )
                )
            if path.startswith(_SSO_MANAGED):
                continue
            age = ctx.days_since(role.get("CreateDate")) or 0
            idle = ctx.days_since((role.get("RoleLastUsed") or {}).get("LastUsedDate"))
            if age > unused_days and (idle is None or idle > unused_days):
                seen = "never (in the tracking period)" if idle is None else f"{idle} days ago"
                findings.append(
                    make(
                        "IAM_ROLE_UNUSED",
                        arn,
                        f"Last used: {seen}.",
                        evidence={"days_since_last_use": idle},
                        confidence=Confidence.MEDIUM,
                    )
                )
        return findings


for _analyzer in (IamRoot(), IamCredentials(), IamPolicies(), IamRoles()):
    register(_analyzer)
