"""Secrets Manager, KMS and RDS analyzers."""

from typing import Any

from fmaws.audit import policies
from fmaws.audit.base import AuditContext, register
from fmaws.audit.findings import make
from fmaws.audit.network import port_open
from fmaws.models.finding import Finding, Severity
from fmaws.models.requirement import Confidence

_KMS_ADMIN = ("kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:CreateGrant")


class Secrets:
    """Rotation only. Over-broad access to secrets is an IAM finding (iam_policies)."""

    name = "secrets"
    regional = True

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        secrets = ctx.pages("secretsmanager", "list_secrets", "SecretList", region)
        # Secrets owned by another AWS service are rotated by that service.
        names = sorted(
            s["Name"]
            for s in secrets
            if not s.get("RotationEnabled") and not s.get("OwningService")
        )
        if not names:
            return []
        shown = ", ".join(names[:10]) + (f" and {len(names) - 10} more" if len(names) > 10 else "")
        return [
            make(
                "SECRETS_ROTATION_DISABLED",
                f"{len(names)} secret(s) in {region}",
                f"Rotation is not configured for: {shown}.",
                evidence={"secrets": names},
            )  # fmt: skip
        ]


class Kms:
    name = "kms"
    regional = True

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        aliases = ctx.pages("kms", "list_aliases", "Aliases", region)
        aws_managed = {
            a.get("TargetKeyId") for a in aliases if a.get("AliasName", "").startswith("alias/aws/")
        }
        trusted = set(ctx.config.audit.trusted_accounts)
        findings: list[Finding] = []
        for key in ctx.pages("kms", "list_keys", "Keys", region):
            if key["KeyId"] in aws_managed:
                continue
            response = ctx.optional(
                "kms", "get_key_policy", region, KeyId=key["KeyId"], PolicyName="default"
            )
            arn = key.get("KeyArn", key["KeyId"])
            public = conditioned = False
            external: dict[str, bool] = {}  # account -> administrative access
            for statement in ctx.statements((response or {}).get("Policy")):
                admin = policies.allows(statement, *_KMS_ADMIN)
                for account in policies.external_accounts(statement, ctx.account, trusted):
                    external[account] = external.get(account, False) or admin
                if policies.is_public(statement) and not policies.is_restricted(statement):
                    if policies.is_conditioned(statement):
                        conditioned = True
                    else:
                        public = True
            if public:
                findings.append(
                    make(
                        "KMS_KEY_PUBLIC",
                        arn,
                        'The key policy allows Principal "*" with no restricting condition.',
                    )  # fmt: skip
                )
            elif conditioned:
                findings.append(
                    make(
                        "KMS_KEY_WILDCARD_PRINCIPAL_CONDITIONED",
                        arn,
                        'The key policy allows Principal "*" limited only by its condition.',
                    )  # fmt: skip
                )
            if external:
                admins = sorted(a for a, is_admin in external.items() if is_admin)
                findings.append(
                    make(
                        "KMS_KEY_CROSS_ACCOUNT",
                        arn,
                        f"External account(s): {', '.join(sorted(external))}."
                        + (
                            f" Administrative actions allowed for: {', '.join(admins)}."
                            if admins
                            else ""
                        ),
                        severity=Severity.HIGH if admins else None,
                        evidence={"accounts": sorted(external)},
                    )  # fmt: skip
                )
        return findings


class Rds:
    name = "rds"
    regional = True

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        instances = ctx.pages("rds", "describe_db_instances", "DBInstances", region)
        public = [i for i in instances if i.get("PubliclyAccessible")]
        groups: dict[str, dict[str, Any]] | None = {}
        group_ids = sorted(
            {g["VpcSecurityGroupId"] for i in public for g in i.get("VpcSecurityGroups", [])}
        )
        if group_ids:
            described = ctx.optional("ec2", "describe_security_groups", region, GroupIds=group_ids)
            groups = (
                None
                if described is None
                else {g["GroupId"]: g for g in described.get("SecurityGroups", [])}
            )

        findings: list[Finding] = []
        for instance in instances:
            arn = instance.get("DBInstanceArn", instance.get("DBInstanceIdentifier", ""))
            port = (instance.get("Endpoint") or {}).get("Port")
            if instance.get("PubliclyAccessible"):
                if groups is None:
                    findings.append(
                        make(
                            "RDS_PUBLICLY_ACCESSIBLE",
                            arn,
                            "The instance is publicly accessible. Its security groups could not "
                            "be read.",
                            confidence=Confidence.MEDIUM,
                        )  # fmt: skip
                    )
                else:
                    exposed = port is not None and any(
                        port_open(groups.get(attached["VpcSecurityGroupId"], {}), port)
                        for attached in instance.get("VpcSecurityGroups", [])
                    )
                    if exposed:
                        findings.append(
                            make(
                                "RDS_PUBLIC_OPEN",
                                arn,
                                f"Publicly accessible and port {port} is open to the internet.",
                            )  # fmt: skip
                        )
                    else:
                        findings.append(
                            make(
                                "RDS_PUBLICLY_ACCESSIBLE",
                                arn,
                                "The instance has a public endpoint; its security groups "
                                "currently restrict the source.",
                            )  # fmt: skip
                        )
            if not instance.get("StorageEncrypted"):
                if instance.get("PubliclyAccessible"):
                    severity = Severity.HIGH
                elif ctx.config.is_production:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                findings.append(
                    make(
                        "RDS_UNENCRYPTED",
                        arn,
                        f"Storage of this {instance.get('Engine', 'database')} instance is not "
                        "encrypted.",
                        severity=severity,
                    )  # fmt: skip
                )
        return findings


for _analyzer in (Secrets(), Kms(), Rds()):
    register(_analyzer)
