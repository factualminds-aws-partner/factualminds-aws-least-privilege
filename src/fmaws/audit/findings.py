"""Audit rules: default severity, category and the fixed text of each finding."""

from dataclasses import dataclass
from typing import Any

from fmaws.models.finding import Finding, Severity
from fmaws.models.requirement import Confidence

EXPOSURE = "exposure"
CREDENTIALS = "credentials"
LEAST_PRIVILEGE = "least-privilege"
LOGGING = "logging"
DATA_PROTECTION = "data-protection"

_IAM = "https://docs.aws.amazon.com/IAM/latest/UserGuide"
_S3 = "https://docs.aws.amazon.com/AmazonS3/latest/userguide"
_BEST = f"{_IAM}/best-practices.html"
_ROOT = f"{_IAM}/root-user-best-practices.html"
_CT = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide"
_KMS = "https://docs.aws.amazon.com/kms/latest/developerguide"
_RDS = "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide"
_SG = "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
_SM = "https://docs.aws.amazon.com/secretsmanager/latest/userguide"
_ROLES = (
    "Use IAM roles and temporary credentials for workloads, and IAM Identity Center for people."
)


@dataclass(frozen=True)
class Rule:
    severity: Severity
    category: str
    service: str
    title: str
    why: str
    fix: str
    url: str


C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

RULES: dict[str, Rule] = {
    # ------------------------------------------------------------------ root user
    "IAM_ROOT_MFA_DISABLED": Rule(
        C, CREDENTIALS, "iam", "Root user has no MFA",
        "The root user cannot be restricted by IAM policies; a stolen password is full account "
        "takeover.",
        "Enable MFA for the root user, or remove root credentials with AWS Organizations "
        "centralized root access. Never use root for applications.",
        _ROOT,
    ),
    "IAM_ROOT_ACCESS_KEYS": Rule(
        C, CREDENTIALS, "iam", "Root user has access keys",
        "Root access keys are long-lived credentials with unrestricted access to the account.",
        f"Delete the root access keys. {_ROLES}",
        _ROOT,
    ),
    "IAM_ROOT_RECENT_USE": Rule(
        M, CREDENTIALS, "iam", "Root user credentials were used recently",
        "Routine root use bypasses least privilege and makes compromise harder to notice.",
        "Confirm the activity was expected. Use root only for tasks that require it.",
        _ROOT,
    ),
    # ------------------------------------------------------------------ IAM credentials
    "IAM_USER_NO_MFA": Rule(
        H, CREDENTIALS, "iam", "IAM user with console access has no MFA",
        "A password alone protects the account; phishing or reuse gives console access.",
        "Enable MFA for the user, or move the person to IAM Identity Center.",
        f"{_BEST}#enable-mfa-for-privileged-users",
    ),
    "IAM_ACCESS_KEY_OLD": Rule(
        M, CREDENTIALS, "iam", "Access key has not been rotated",
        "Long-lived keys accumulate exposure in laptops, CI systems and repositories.",
        f"Replace the key with temporary credentials. {_ROLES} If a key is unavoidable, "
        "create a new one, switch the workload, then delete the old key.",
        f"{_BEST}#rotate-credentials",
    ),
    "IAM_ACCESS_KEY_UNUSED": Rule(
        M, CREDENTIALS, "iam", "Active access key is not used",
        "An unused active key is attack surface with no benefit.",
        "Deactivate the key, confirm nothing breaks, then delete it.",
        f"{_IAM}/id_credentials_finding-unused.html",
    ),
    "IAM_USER_INACTIVE": Rule(
        L, CREDENTIALS, "iam", "IAM user has not signed in or used keys recently",
        "Dormant users keep their permissions and are rarely monitored.",
        "Confirm with the owner and remove the user or its credentials.",
        f"{_IAM}/id_credentials_finding-unused.html",
    ),
    # ------------------------------------------------------------------ IAM permissions
    "IAM_ADMIN_ATTACHED": Rule(
        H, LEAST_PRIVILEGE, "iam", "AdministratorAccess is attached",
        "The principal can do anything in the account, including changing its own permissions.",
        "Replace AdministratorAccess with a policy scoped to what the principal does. "
        "Keep administrator access to a small number of human break-glass roles.",
        f"{_BEST}#grant-least-privilege",
    ),
    "IAM_POLICY_ADMIN": Rule(
        H, LEAST_PRIVILEGE, "iam", "Customer policy grants every action on every resource",
        "It is equivalent to AdministratorAccess but harder to spot.",
        "Replace the statement with explicit actions on specific resources.",
        f"{_BEST}#grant-least-privilege",
    ),
    "IAM_POLICY_ACTION_WILDCARD": Rule(
        H, LEAST_PRIVILEGE, "iam", 'Policy allows Action "*"',
        "Every current and future action is allowed on the listed resources.",
        "List the specific actions that are needed.",
        f"{_BEST}#grant-least-privilege",
    ),
    "IAM_POLICY_NOT_ACTION": Rule(
        H, LEAST_PRIVILEGE, "iam", "Policy uses Allow with NotAction",
        "Everything except the listed actions is allowed, including actions AWS adds later.",
        "Use Action with an explicit list.",
        f"{_IAM}/reference_policies_elements_notaction.html",
    ),
    "IAM_POLICY_SERVICE_WILDCARD": Rule(
        M, LEAST_PRIVILEGE, "iam", "Policy allows every action of a service",
        "Service wildcards include destructive and administrative actions.",
        "List the specific actions that are needed. fmaws generate can produce them.",
        f"{_BEST}#grant-least-privilege",
    ),
    "IAM_POLICY_PASSROLE": Rule(
        H, LEAST_PRIVILEGE, "iam", "Policy allows iam:PassRole on every role",
        "Passing any role to a service is a well-known privilege escalation path.",
        "Restrict Resource to specific role ARNs and add an iam:PassedToService condition.",
        f"{_IAM}/id_roles_use_passrole.html",
    ),
    "IAM_POLICY_PRIVILEGE_ESCALATION": Rule(
        H, LEAST_PRIVILEGE, "iam", "Policy allows IAM privilege escalation",
        "The holder can grant itself more permissions or assume any role.",
        "Remove the actions or restrict Resource to specific users, roles or policies.",
        f"{_BEST}#grant-least-privilege",
    ),
    "IAM_POLICY_RESOURCE_WILDCARD": Rule(
        M, LEAST_PRIVILEGE, "iam", 'Policy uses Resource "*" where specific resources are possible',
        "The actions apply to every resource of that type in the account.",
        "Scope Resource to the ARNs that are used.",
        f"{_BEST}#grant-least-privilege",
    ),
    "IAM_SECRETS_WILDCARD_ACCESS": Rule(
        H, LEAST_PRIVILEGE, "secretsmanager", "Policy can read every secret",
        "One compromised principal exposes every credential stored in Secrets Manager.",
        "Restrict secretsmanager:GetSecretValue to the secret ARNs the workload needs.",
        f"{_SM}/auth-and-access_iam-policies.html",
    ),
    "IAM_DYNAMODB_WILDCARD_ACCESS": Rule(
        M, LEAST_PRIVILEGE, "dynamodb", "Policy grants data access to every DynamoDB table",
        "The principal can read or change data of unrelated applications and tenants.",
        "Restrict the statement to the table (and index) ARNs the workload uses.",
        "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/"
        "security_iam_service-with-iam.html",
    ),
    "IAM_USER_INLINE_POLICY": Rule(
        L, LEAST_PRIVILEGE, "iam", "IAM user has inline policies",
        "Inline user policies are hard to review and tie permissions to long-lived identities.",
        "Move the permissions to a role or a managed policy attached to a group.",
        f"{_IAM}/access_policies_managed-vs-inline.html",
    ),
    # ------------------------------------------------------------------ IAM roles
    "IAM_ROLE_TRUST_PUBLIC": Rule(
        C, EXPOSURE, "iam", "Role can be assumed by any AWS principal",
        "Any AWS account can assume the role and use its permissions.",
        "Name the specific principals in the trust policy.",
        f"{_IAM}/reference_policies_elements_principal.html",
    ),
    "IAM_ROLE_TRUST_CROSS_ACCOUNT": Rule(
        M, LEAST_PRIVILEGE, "iam", "Role trusts another AWS account",
        "The other account decides who can use this role's permissions.",
        "Confirm the account is yours or a trusted vendor, require sts:ExternalId for third "
        "parties, and list it under audit.trusted_accounts.",
        f"{_IAM}/confused-deputy.html",
    ),
    "IAM_ROLE_TRUST_OIDC_UNRESTRICTED": Rule(
        H, EXPOSURE, "iam", "OIDC role does not restrict the token subject",
        "Any identity of that provider, for example any GitHub repository, can assume the role.",
        'Add a condition on the provider\'s ":sub" claim that names your repository or workload.',
        f"{_IAM}/id_roles_create_for-idp_oidc.html",
    ),
    "IAM_ROLE_UNUSED": Rule(
        L, LEAST_PRIVILEGE, "iam", "Role has not been used recently",
        "Unused roles keep their permissions and trust relationships.",
        "Confirm with the owner and delete the role.",
        f"{_IAM}/id_roles_manage_delete.html",
    ),
    # ------------------------------------------------------------------ S3
    "S3_ACCOUNT_BPA_DISABLED": Rule(
        M, EXPOSURE, "s3", "Account-level S3 Block Public Access is not fully enabled",
        "Nothing prevents a bucket in this account from being made public by mistake.",
        "Enable all four Block Public Access settings for the account. Serve public content "
        "through CloudFront.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_PUBLIC_WRITE": Rule(
        C, EXPOSURE, "s3", "Bucket allows public write access",
        "Anonymous users may upload or modify objects.",
        "Enable S3 Block Public Access and remove public-write bucket policy statements "
        "and ACL grants.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_PUBLIC_DELETE": Rule(
        C, EXPOSURE, "s3", "Bucket allows public delete access",
        "Anonymous users may delete objects or the bucket.",
        "Enable S3 Block Public Access and remove the public statement.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_PUBLIC_READ": Rule(
        H, EXPOSURE, "s3", "Bucket allows public read access",
        "Anyone on the internet can read or list the objects.",
        "Enable S3 Block Public Access and remove the public statement. If the bucket is "
        "meant to be public, list it under audit.intentional_public.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_PUBLIC_READ_INTENTIONAL": Rule(
        Severity.INFO, EXPOSURE, "s3", "Bucket is public by design",
        "The bucket is listed under audit.intentional_public.",
        "Review periodically that only public content is stored in it.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_PUBLIC_BLOCKED": Rule(
        L, EXPOSURE, "s3", "Bucket has public grants that Block Public Access overrides",
        "The bucket becomes public the moment Block Public Access is relaxed.",
        "Remove the public policy statements and ACL grants.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_WILDCARD_PRINCIPAL_CONDITIONED": Rule(
        M, EXPOSURE, "s3", "Bucket policy allows any principal under a condition",
        "Access depends entirely on the condition; fmaws cannot verify that it restricts callers.",
        "Name the principals, or use aws:PrincipalOrgID, aws:SourceVpce or aws:SourceIp.",
        f"{_S3}/example-bucket-policies.html",
    ),
    "S3_CROSS_ACCOUNT_ACCESS": Rule(
        M, LEAST_PRIVILEGE, "s3", "Bucket policy grants access to another AWS account",
        "The other account controls who can reach the data.",
        "Confirm the account is trusted and list it under audit.trusted_accounts, or remove "
        "the statement.",
        f"{_S3}/example-walkthroughs-managing-access-example2.html",
    ),
    "S3_BUCKET_BPA_DISABLED": Rule(
        L, EXPOSURE, "s3", "Buckets without full Block Public Access",
        "Neither the account nor these buckets block public policies and ACLs.",
        "Enable Block Public Access at account level, or on each bucket.",
        f"{_S3}/access-control-block-public-access.html",
    ),
    "S3_ACLS_ENABLED": Rule(
        L, EXPOSURE, "s3", "Buckets with ACLs enabled",
        "ACLs are a second, hard to audit access mechanism.",
        "Set Object Ownership to Bucket owner enforced.",
        f"{_S3}/about-object-ownership.html",
    ),
    "S3_VERSIONING_DISABLED": Rule(
        L, DATA_PROTECTION, "s3", "Buckets without versioning",
        "Overwritten or deleted objects cannot be recovered.",
        "Enable versioning on buckets that hold data you cannot regenerate.",
        f"{_S3}/Versioning.html",
    ),
    "S3_LOGGING_DISABLED": Rule(
        Severity.INFO, LOGGING, "s3", "Buckets without server access logging",
        "Object-level access cannot be reconstructed. CloudTrail data events are an alternative.",
        "Enable access logging or CloudTrail data events for sensitive buckets.",
        f"{_S3}/ServerLogs.html",
    ),
    "S3_ENCRYPTION_MISSING": Rule(
        L, DATA_PROTECTION, "s3", "Bucket has no default encryption configuration",
        "New objects may be stored unencrypted.",
        "Configure default encryption (SSE-S3 or SSE-KMS).",
        f"{_S3}/bucket-encryption.html",
    ),
    # ------------------------------------------------------------------ network
    "SG_OPEN_ALL_PORTS": Rule(
        C, EXPOSURE, "ec2", "Security group allows all ports from the internet",
        "Every service on the attached resources is reachable by anyone.",
        "Restrict the rule to the ports and source ranges that are required.",
        _SG,
    ),
    "SG_OPEN_SENSITIVE_PORT": Rule(
        H, EXPOSURE, "ec2",
        "Security group exposes administrative or database ports to the internet",
        "SSH, RDP and database ports are scanned and attacked continuously.",
        "Restrict the source to known ranges, or use Session Manager, a VPN or private "
        "connectivity.",
        _SG,
    ),
    # ------------------------------------------------------------------ CloudTrail
    "CLOUDTRAIL_NO_TRAIL": Rule(
        H, LOGGING, "cloudtrail", "No CloudTrail trail",
        "Only 90 days of management events are kept and nothing is delivered for analysis or "
        "alerting.",
        "Create a multi-Region trail that logs management events to a protected bucket.",
        f"{_CT}/cloudtrail-create-and-update-a-trail.html",
    ),
    "CLOUDTRAIL_NOT_LOGGING": Rule(
        H, LOGGING, "cloudtrail", "No trail is logging in some audited Regions",
        "API activity in those Regions is not delivered anywhere.",
        "Start logging on the trail or create a multi-Region trail.",
        f"{_CT}/cloudtrail-create-and-update-a-trail.html",
    ),
    "CLOUDTRAIL_NOT_MULTI_REGION": Rule(
        M, LOGGING, "cloudtrail", "No multi-Region trail",
        "Activity in Regions you do not use, a common sign of compromise, goes unrecorded.",
        "Convert a trail to multi-Region.",
        f"{_CT}/receive-cloudtrail-log-files-from-multiple-regions.html",
    ),
    "CLOUDTRAIL_MANAGEMENT_EVENTS_GAP": Rule(
        M, LOGGING, "cloudtrail", "No trail records all management events",
        "Read or write management events are missing from the delivered logs.",
        "Configure a trail to log management events with read and write events.",
        f"{_CT}/logging-management-events-with-cloudtrail.html",
    ),
    "CLOUDTRAIL_LOG_VALIDATION_DISABLED": Rule(
        L, LOGGING, "cloudtrail", "Trail has log file validation disabled",
        "Tampering with delivered log files cannot be detected.",
        "Enable log file validation on the trail.",
        f"{_CT}/cloudtrail-log-file-validation-intro.html",
    ),
    "CLOUDTRAIL_BUCKET_PUBLIC": Rule(
        C, EXPOSURE, "cloudtrail", "CloudTrail log bucket is public",
        "The account's API activity, including resource names and caller identities, is exposed.",
        "Remove public access from the bucket and enable Block Public Access.",
        f"{_CT}/create-s3-bucket-policy-for-cloudtrail.html",
    ),
    # ------------------------------------------------------------------ secrets, KMS, RDS
    "SECRETS_ROTATION_DISABLED": Rule(
        L, DATA_PROTECTION, "secretsmanager", "Secrets without automatic rotation",
        "A leaked secret stays valid until someone notices.",
        "Enable rotation where the secret type supports it. fmaws never rotates anything.",
        f"{_SM}/rotating-secrets.html",
    ),
    "KMS_KEY_PUBLIC": Rule(
        C, EXPOSURE, "kms", "KMS key policy allows any principal",
        "Any AWS account can use or administer the key.",
        "Name specific principals, or add kms:CallerAccount and kms:ViaService conditions.",
        f"{_KMS}/key-policies.html",
    ),
    "KMS_KEY_WILDCARD_PRINCIPAL_CONDITIONED": Rule(
        M, EXPOSURE, "kms", "KMS key policy allows any principal under a condition",
        "Access depends entirely on the condition; fmaws cannot verify that it restricts callers.",
        "Name the principals, or use kms:CallerAccount or aws:PrincipalOrgID.",
        f"{_KMS}/key-policies.html",
    ),
    "KMS_KEY_CROSS_ACCOUNT": Rule(
        M, LEAST_PRIVILEGE, "kms", "KMS key policy grants access to another AWS account",
        "The other account can use the key within the allowed actions.",
        "Confirm the account is trusted and list it under audit.trusted_accounts, and limit "
        "the actions to the cryptographic operations it needs.",
        f"{_KMS}/key-policy-modifying-external-accounts.html",
    ),
    "RDS_PUBLIC_OPEN": Rule(
        C, EXPOSURE, "rds", "Database is reachable from the internet",
        "The instance is publicly accessible and its security group accepts connections "
        "from anywhere.",
        "Disable public accessibility and restrict the security group to application sources.",
        f"{_RDS}/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
    ),
    "RDS_PUBLICLY_ACCESSIBLE": Rule(
        M, EXPOSURE, "rds", "Database has a public endpoint",
        "A single security group change exposes the database to the internet.",
        "Disable public accessibility and reach the database through private networking.",
        f"{_RDS}/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
    ),
    "RDS_UNENCRYPTED": Rule(
        M, DATA_PROTECTION, "rds", "Database storage is not encrypted",
        "Snapshots and underlying storage hold the data in clear text.",
        "Encryption cannot be enabled in place: restore an encrypted copy of a snapshot and "
        "switch over.",
        f"{_RDS}/Overview.Encryption.html",
    ),
}  # fmt: skip


def make(
    rule_id: str,
    resource: str,
    problem: str,
    *,
    severity: Severity | None = None,
    evidence: dict[str, Any] | None = None,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        id=rule_id,
        severity=severity or rule.severity,
        category=rule.category,
        service=rule.service,
        resource=resource,
        title=rule.title,
        problem=problem,
        why_it_matters=rule.why,
        evidence=evidence or {},
        recommendation=rule.fix,
        remediation=rule.fix,
        documentation_url=rule.url,
        confidence=confidence,
    )


def shown(names: list[str], limit: int = 10) -> str:
    """The first names, and how many more there are."""
    rest = len(names) - limit
    return ", ".join(names[:limit]) + (f" and {rest} more" if rest > 0 else "")
