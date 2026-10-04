import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from typer.testing import CliRunner

from fmaws.audit.base import (
    OPERATIONS,
    AuditContext,
    apply_config,
    permission_manifest,
    resolve_regions,
    run_audit,
)
from fmaws.audit.scoring import score, scores
from fmaws.aws.session import AWSClientProvider
from fmaws.cli.app import app
from fmaws.config.schema import Config
from fmaws.errors import AwsAuthError, ConfigError
from fmaws.models.finding import Severity
from fmaws.models.report import Report
from fmaws.reporters.base import render
from tests.conftest import REPO

NOW = datetime(2026, 10, 4, tzinfo=UTC)
ACCOUNT = "111122223333"
OTHER = "999900001111"
runner = CliRunner()


def ago(days):
    return NOW - timedelta(days=days)


def iso(days):
    return ago(days).isoformat()


def error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Operation")


COLUMNS = (
    "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date"
).split(",")


def report(*rows):
    root = {"user": "<root_account>", "arn": f"arn:aws:iam::{ACCOUNT}:root",
            "password_enabled": "not_supported", "password_last_used": "no_information",
            "mfa_active": "true"}  # fmt: skip
    lines = [",".join(COLUMNS)]
    for row in (root, *rows):
        lines.append(",".join(str(row.get(c, "N/A")) for c in COLUMNS))
    return {"Content": "\n".join(lines).encode()}


def user(name, **fields):
    base = {"user": name, "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
            "user_creation_time": iso(400), "password_enabled": "false", "mfa_active": "false",
            "access_key_1_active": "false", "access_key_2_active": "false"}  # fmt: skip
    return {**base, **fields}


def details(users=(), groups=(), roles=(), policies=()):
    return {"UserDetailList": list(users), "GroupDetailList": list(groups),
            "RoleDetailList": list(roles), "Policies": list(policies)}  # fmt: skip


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def role(name, trust, path="/", created=400, used=1, **extra):
    last = {"LastUsedDate": ago(used)} if used is not None else {}
    return {"RoleName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:role{path}{name}", "Path": path,
            "CreateDate": ago(created), "AssumeRolePolicyDocument": trust, "RoleLastUsed": last,
            "RolePolicyList": [], "AttachedManagedPolicies": [], **extra}  # fmt: skip


SERVICE_TRUST = doc({"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                     "Action": "sts:AssumeRole"})  # fmt: skip
BPA_ON = {"PublicAccessBlockConfiguration": dict.fromkeys(
    ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)}  # fmt: skip
BPA_OFF = error("NoSuchPublicAccessBlockConfiguration")
TRAIL = {"Name": "main", "TrailARN": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/main",
         "HomeRegion": "us-east-1", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True,
         "S3BucketName": "trail-logs"}  # fmt: skip


def healthy():
    """Responses of an account with nothing to report."""
    return {
        ("iam", "get_account_summary"): {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        },
        ("iam", "generate_credential_report"): {"State": "COMPLETE"},
        ("iam", "get_credential_report"): report(),
        ("iam", "get_account_authorization_details"): details(),
        ("s3", "list_buckets"): {"Buckets": []},
        ("s3control", "get_public_access_block"): BPA_ON,
        ("s3", "get_bucket_policy_status"): {"PolicyStatus": {"IsPublic": False}},
        ("ec2", "describe_security_groups"): {"SecurityGroups": []},
        ("ec2", "describe_network_interfaces"): {"NetworkInterfaces": []},
        ("cloudtrail", "describe_trails"): {"trailList": [TRAIL]},
        ("cloudtrail", "get_trail_status"): {"IsLogging": True},
        ("cloudtrail", "get_event_selectors"): {
            "EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]
        },
        ("secretsmanager", "list_secrets"): {"SecretList": []},
        ("kms", "list_aliases"): {"Aliases": []},
        ("kms", "list_keys"): {"Keys": []},
        ("rds", "describe_db_instances"): {"DBInstances": []},
    }


class FakeAWS:
    """Canned responses per (service, operation). Values may be callables or exceptions."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def client(self, service, region=None):
        aws = self

        class Client:
            def can_paginate(self, operation):
                return False

            def __getattr__(self, operation):
                def invoke(**kwargs):
                    aws.calls.append((service, operation, region, kwargs))
                    if (service, operation) not in aws.responses:
                        raise AssertionError(f"unexpected call {service}.{operation}")
                    value = aws.responses[(service, operation)]
                    if callable(value):
                        value = value(region=region, **kwargs)
                    if isinstance(value, Exception):
                        raise value
                    return value

                return invoke

        return Client()


def run(overrides=None, config=None, regions=("us-east-1",)):
    aws = FakeAWS({**healthy(), **(overrides or {})})
    provider = AWSClientProvider()
    provider.client = aws.client
    settings = Config.model_validate({"audit": {"concurrency": 1, **(config or {})}})
    ctx = AuditContext(provider, ACCOUNT, list(regions), settings, now=NOW)
    findings, statuses = run_audit(ctx)
    return findings, statuses, aws


def found(overrides=None, config=None, **kwargs):
    findings, _, _ = run(overrides, config, **kwargs)
    return {(f.id, f.severity) for f in findings}


def ids(overrides=None, config=None, **kwargs):
    return {f.id for f in run(overrides, config, **kwargs)[0]}


# ------------------------------------------------------------------ baseline


def test_healthy_account_has_no_findings_and_every_analyzer_completes():
    findings, statuses, _ = run()
    assert findings == []
    assert [s.status for s in statuses] == ["completed"] * 10
    assert scores(findings) == {"security": 100, "least_privilege": 100}


# ------------------------------------------------------------------ IAM root and credentials


def test_root_user_findings():
    assert found({
        ("iam", "get_account_summary"): {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}
        },
    }) == {
        ("IAM_ROOT_MFA_DISABLED", Severity.CRITICAL),
        ("IAM_ROOT_ACCESS_KEYS", Severity.CRITICAL),
    }  # fmt: skip


def test_root_recent_use_and_centrally_managed_root():
    summary = {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}}

    def with_root(**fields):
        lines = [",".join(COLUMNS)]
        row = {"user": "<root_account>", "arn": "arn", **fields}
        lines.append(",".join(str(row.get(c, "N/A")) for c in COLUMNS))
        return {"Content": "\n".join(lines).encode()}

    recent = with_root(password_enabled="not_supported", password_last_used=iso(3))
    assert found(
        {("iam", "get_account_summary"): summary, ("iam", "get_credential_report"): recent}
    ) == {
        ("IAM_ROOT_MFA_DISABLED", Severity.CRITICAL),
        ("IAM_ROOT_RECENT_USE", Severity.MEDIUM),
    }
    removed = with_root(password_enabled="false")
    assert (
        found({("iam", "get_account_summary"): summary, ("iam", "get_credential_report"): removed})
        == set()
    )


def test_credential_findings():
    rows = report(
        user("console-no-mfa", password_enabled="true", password_last_used=iso(2)),
        user("old-key", access_key_1_active="true", access_key_1_last_rotated=iso(200),
             access_key_1_last_used_date=iso(1)),
        user("unused-key", access_key_1_active="true", access_key_1_last_rotated=iso(200)),
        user("idle-key", access_key_2_active="true", access_key_2_last_rotated=iso(300),
             access_key_2_last_used_date=iso(150)),
        user("dormant", password_enabled="true", mfa_active="true", password_last_used=iso(200)),
        user("healthy", password_enabled="true", mfa_active="true", password_last_used=iso(1),
             access_key_1_active="true", access_key_1_last_rotated=iso(10),
             access_key_1_last_used_date=iso(1)),
        user("new-key-never-used", access_key_1_active="true", access_key_1_last_rotated=iso(5)),
    )  # fmt: skip
    findings, _, _ = run({("iam", "get_credential_report"): rows})
    by_user = {(f.resource.split("/")[-1], f.id) for f in findings}
    assert by_user == {
        ("console-no-mfa", "IAM_USER_NO_MFA"),
        ("old-key", "IAM_ACCESS_KEY_OLD"),
        ("unused-key", "IAM_ACCESS_KEY_UNUSED"),
        ("idle-key", "IAM_ACCESS_KEY_UNUSED"),
        ("dormant", "IAM_USER_INACTIVE"),
    }
    old = next(f for f in findings if f.id == "IAM_ACCESS_KEY_OLD")
    assert "roles" in old.problem and old.remediation


def test_key_age_limit_is_configurable():
    rows = report(user("k", access_key_1_active="true", access_key_1_last_rotated=iso(120),
                       access_key_1_last_used_date=iso(1)))  # fmt: skip
    assert ids({("iam", "get_credential_report"): rows}) == {"IAM_ACCESS_KEY_OLD"}
    assert ids({("iam", "get_credential_report"): rows}, {"max_access_key_age_days": 180}) == set()


# ------------------------------------------------------------------ IAM permissions


def managed(name, document, attached=1):
    return {"PolicyName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:policy/{name}",
            "AttachmentCount": attached,
            "PolicyVersionList": [{"IsDefaultVersion": True, "Document": document},
                                  {"IsDefaultVersion": False, "Document": doc(allow("*"))}]}  # fmt: skip


def with_details(**kwargs):
    return {("iam", "get_account_authorization_details"): details(**kwargs)}


def test_customer_policy_breadth_depends_on_attachment():
    admin = doc(allow("*"))
    assert found(with_details(policies=[managed("admin", admin)])) == {
        ("IAM_POLICY_ADMIN", Severity.HIGH)
    }
    assert found(with_details(policies=[managed("admin", admin, attached=0)])) == {
        ("IAM_POLICY_ADMIN", Severity.LOW)
    }
    scoped = doc(allow("s3:GetObject", "arn:aws:s3:::bucket-one/a/*"))
    assert found(with_details(policies=[managed("scoped", scoped)])) == set()


def test_only_the_default_policy_version_is_judged():
    safe = doc(allow("sqs:SendMessage", f"arn:aws:sqs:us-east-1:{ACCOUNT}:q"))
    assert found(with_details(policies=[managed("p", safe)])) == set()


def test_dangerous_statements_in_policies():
    policy = doc(
        allow("iam:PassRole"),
        allow("s3:*"),
        allow("iam:AttachRolePolicy"),
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
    )
    assert found(with_details(policies=[managed("p", policy)])) >= {
        ("IAM_POLICY_PASSROLE", Severity.HIGH),
        ("IAM_POLICY_SERVICE_WILDCARD", Severity.HIGH),
        ("IAM_POLICY_PRIVILEGE_ESCALATION", Severity.HIGH),
        ("IAM_POLICY_NOT_ACTION", Severity.HIGH),
    }


def test_secrets_and_dynamodb_wildcard_access():
    policy = doc(
        allow("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{ACCOUNT}:secret:*"),
        allow(["dynamodb:GetItem", "dynamodb:PutItem"], f"arn:aws:dynamodb:*:{ACCOUNT}:table/*"),
    )
    assert found(with_details(policies=[managed("p", policy)])) >= {
        ("IAM_SECRETS_WILDCARD_ACCESS", Severity.HIGH),
        ("IAM_DYNAMODB_WILDCARD_ACCESS", Severity.MEDIUM),
    }
    narrow = doc(
        allow("secretsmanager:GetSecretValue",
              f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:prod/api-??????"),
        allow("dynamodb:GetItem", f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders"),
    )  # fmt: skip
    assert found(with_details(policies=[managed("p", narrow)])) == set()


def test_administrator_access_severity_depends_on_the_principal():
    admin = [{"PolicyName": "AdministratorAccess",
              "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]  # fmt: skip
    person = {"UserName": "ops", "Arn": f"arn:aws:iam::{ACCOUNT}:user/ops", "Path": "/",
              "UserPolicyList": [], "AttachedManagedPolicies": admin}  # fmt: skip
    assert found(with_details(users=[person])) == {("IAM_ADMIN_ATTACHED", Severity.HIGH)}
    break_glass = role("break-glass", SERVICE_TRUST, AttachedManagedPolicies=admin)
    assert found(with_details(roles=[break_glass])) == {("IAM_ADMIN_ATTACHED", Severity.MEDIUM)}
    sso = role("AWSReservedSSO_Admin_abc", SERVICE_TRUST, AttachedManagedPolicies=admin,
               path="/aws-reserved/sso.amazonaws.com/", used=None)  # fmt: skip
    assert found(with_details(roles=[sso])) == set()


def test_inline_policies_and_service_linked_roles():
    inline = [{"PolicyName": "everything", "PolicyDocument": doc(allow("*"))}]
    person = {"UserName": "dev", "Arn": f"arn:aws:iam::{ACCOUNT}:user/dev", "Path": "/",
              "UserPolicyList": inline, "AttachedManagedPolicies": []}  # fmt: skip
    findings, _, _ = run(with_details(users=[person]))
    assert {f.id for f in findings} == {"IAM_POLICY_ADMIN", "IAM_USER_INLINE_POLICY"}
    assert any("inline policy everything" in f.resource for f in findings)
    linked = role("AWSServiceRoleForX", SERVICE_TRUST, path="/aws-service-role/x.amazonaws.com/",
                  RolePolicyList=inline, used=None)  # fmt: skip
    assert found(with_details(roles=[linked])) == set()


# ------------------------------------------------------------------ IAM roles


def trust(principal, condition=None, action="sts:AssumeRole"):
    statement = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        statement["Condition"] = condition
    return doc(statement)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (trust("*"), {("IAM_ROLE_TRUST_PUBLIC", Severity.CRITICAL)}),
        (trust({"AWS": "*"}, {"StringLike": {"aws:userid": "AROA*"}}),
         {("IAM_ROLE_TRUST_PUBLIC", Severity.MEDIUM)}),
        (trust({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}), set()),
        (trust({"AWS": f"arn:aws:iam::{OTHER}:root"}),
         {("IAM_ROLE_TRUST_CROSS_ACCOUNT", Severity.MEDIUM)}),
        (trust({"AWS": f"arn:aws:iam::{OTHER}:root"}, {"StringEquals": {"sts:ExternalId": "s3cr3t"}}),
         {("IAM_ROLE_TRUST_CROSS_ACCOUNT", Severity.LOW)}),
        (trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}), set()),
        (SERVICE_TRUST, set()),
    ],
)  # fmt: skip
def test_role_trust(document, expected):
    assert found(with_details(roles=[role("r", document)])) == expected


def test_trusted_accounts_are_not_reported():
    external = role("r", trust({"AWS": [OTHER]}))
    assert ids(with_details(roles=[external])) == {"IAM_ROLE_TRUST_CROSS_ACCOUNT"}
    assert ids(with_details(roles=[external]), {"trusted_accounts": [OTHER]}) == set()


def test_oidc_role_must_pin_the_subject():
    provider = {
        "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    }
    action = "sts:AssumeRoleWithWebIdentity"
    audience_only = trust(provider, {"StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}, action)  # fmt: skip
    assert found(with_details(roles=[role("ci", audience_only)])) == {
        ("IAM_ROLE_TRUST_OIDC_UNRESTRICTED", Severity.HIGH)
    }
    wildcard = trust(
        provider, {"StringLike": {"token.actions.githubusercontent.com:sub": "*"}}, action
    )
    assert ids(with_details(roles=[role("ci", wildcard)])) == {"IAM_ROLE_TRUST_OIDC_UNRESTRICTED"}
    pinned = trust(provider, {"StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:acme/shop:*"}}, action)  # fmt: skip
    assert found(with_details(roles=[role("ci", pinned)])) == set()


def test_unused_roles_need_reliable_evidence():
    assert found(with_details(roles=[role("old", SERVICE_TRUST, used=200)])) == {
        ("IAM_ROLE_UNUSED", Severity.LOW)
    }
    assert ids(with_details(roles=[role("never", SERVICE_TRUST, used=None)])) == {"IAM_ROLE_UNUSED"}
    assert ids(with_details(roles=[role("new", SERVICE_TRUST, created=5, used=None)])) == set()


# ------------------------------------------------------------------ S3


def s3_account(buckets, account_bpa=BPA_OFF, **per_bucket):
    """per_bucket: operation name -> {bucket: response}. Unlisted buckets get a neutral answer."""
    neutral = {
        "get_public_access_block": BPA_OFF,
        "get_bucket_policy": error("NoSuchBucketPolicy"),
        "get_bucket_acl": {"Grants": []},
        "get_bucket_ownership_controls": {
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
        },
        "get_bucket_versioning": {"Status": "Enabled"},
        "get_bucket_logging": {"LoggingEnabled": {"TargetBucket": "logs"}},
        "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{}]}},
    }
    responses = {
        ("s3", "list_buckets"): {"Buckets": [{"Name": b} for b in buckets]},
        ("s3control", "get_public_access_block"): account_bpa,
    }
    for operation, default in neutral.items():
        overrides = per_bucket.get(operation, {})
        responses[("s3", operation)] = (
            lambda region=None, Bucket=None, _o=overrides, _d=default, **_: _o.get(Bucket, _d)
        )
    return responses


def bucket_policy(*statements):
    return {"Policy": json.dumps(doc(*statements))}


def public(action, name, **extra):
    return {"Effect": "Allow", "Principal": "*", "Action": action,
            "Resource": f"arn:aws:s3:::{name}/*", **extra}  # fmt: skip


def test_public_buckets_by_policy():
    responses = s3_account(
        ["writable", "readable", "private"],
        get_bucket_policy={
            "writable": bucket_policy(public(["s3:PutObject", "s3:DeleteObject"], "writable")),
            "readable": bucket_policy(public("s3:GetObject", "readable")),
        },
    )
    findings, _, _ = run(responses)
    by_bucket = {(f.resource, f.id, f.severity) for f in findings if "PUBLIC_" in f.id}
    assert by_bucket == {
        ("arn:aws:s3:::writable", "S3_PUBLIC_WRITE", Severity.CRITICAL),
        ("arn:aws:s3:::writable", "S3_PUBLIC_DELETE", Severity.CRITICAL),
        ("arn:aws:s3:::readable", "S3_PUBLIC_READ", Severity.HIGH),
    }
    write = next(f for f in findings if f.id == "S3_PUBLIC_WRITE")
    assert "Block Public Access" in write.remediation


def test_wildcard_actions_count_as_public_write():
    responses = s3_account(["b1"], get_bucket_policy={"b1": bucket_policy(public("s3:*", "b1"))})
    assert {"S3_PUBLIC_WRITE", "S3_PUBLIC_DELETE", "S3_PUBLIC_READ"} <= ids(responses)


def test_intentional_public_read_is_info_but_public_write_is_never_excused():
    responses = s3_account(
        ["site", "drop"],
        get_bucket_policy={
            "site": bucket_policy(public("s3:GetObject", "site")),
            "drop": bucket_policy(public("s3:PutObject", "drop")),
        },
    )
    result = found(responses, {"intentional_public": ["site", "drop"]})
    assert ("S3_PUBLIC_READ_INTENTIONAL", Severity.INFO) in result
    assert ("S3_PUBLIC_WRITE", Severity.CRITICAL) in result
    assert "S3_PUBLIC_READ" not in {i for i, _ in result}


def test_block_public_access_overrides_public_grants():
    policy = {"b1": bucket_policy(public("s3:GetObject", "b1"))}
    blocked = s3_account(["b1"], account_bpa=BPA_ON, get_bucket_policy=policy)
    assert found(blocked) == {("S3_PUBLIC_BLOCKED", Severity.LOW)}
    bucket_level = s3_account(["b1"], get_bucket_policy=policy,
                              get_public_access_block={"b1": BPA_ON})  # fmt: skip
    assert ids(bucket_level) == {"S3_ACCOUNT_BPA_DISABLED", "S3_PUBLIC_BLOCKED"}


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ({"StringEquals": {"aws:SourceVpce": "vpce-1a2b3c"}}, set()),
        ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, set()),
        ({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}, {"S3_WILDCARD_PRINCIPAL_CONDITIONED"}),
        ({"Bool": {"aws:SecureTransport": "true"}}, {"S3_WILDCARD_PRINCIPAL_CONDITIONED"}),
        ({"StringLike": {"aws:PrincipalArn": "*"}}, {"S3_PUBLIC_READ"}),
        ({"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}, {"S3_WILDCARD_PRINCIPAL_CONDITIONED"}),
    ],
)
def test_conditions_on_a_wildcard_principal(condition, expected):
    policy = bucket_policy(public("s3:GetObject", "b1", Condition=condition))
    result = ids(s3_account(["b1"], get_bucket_policy={"b1": policy}))
    assert result - {"S3_ACCOUNT_BPA_DISABLED", "S3_BUCKET_BPA_DISABLED"} == expected


def test_public_acl_grants():
    everyone = {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}
    acl = {"b1": {"Grants": [{"Grantee": everyone, "Permission": "WRITE"}]}}
    enabled = {"b1": error("OwnershipControlsNotFoundError")}
    responses = s3_account(["b1"], get_bucket_acl=acl, get_bucket_ownership_controls=enabled)
    assert {"S3_PUBLIC_WRITE", "S3_ACLS_ENABLED"} <= ids(responses)
    # With bucket-owner-enforced ownership the ACL has no effect.
    assert "S3_PUBLIC_WRITE" not in ids(s3_account(["b1"], get_bucket_acl=acl))


def test_cross_account_bucket_access():
    def grant(action):
        return bucket_policy({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
                              "Action": action, "Resource": "arn:aws:s3:::b1/*"})  # fmt: skip

    read = s3_account(["b1"], account_bpa=BPA_ON, get_bucket_policy={"b1": grant("s3:GetObject")})
    assert found(read) == {("S3_CROSS_ACCOUNT_ACCESS", Severity.LOW)}
    write = s3_account(["b1"], account_bpa=BPA_ON, get_bucket_policy={"b1": grant("s3:PutObject")})
    assert found(write) == {("S3_CROSS_ACCOUNT_ACCESS", Severity.MEDIUM)}
    assert found(write, {"trusted_accounts": [OTHER]}) == set()


def test_defense_in_depth_findings_are_aggregated():
    names = [f"bucket-{i:02d}" for i in range(12)]
    responses = s3_account(
        names,
        get_bucket_versioning=dict.fromkeys(names, {}),
        get_bucket_logging=dict.fromkeys(names, {}),
    )
    findings, _, _ = run(responses)
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {
        "S3_ACCOUNT_BPA_DISABLED", "S3_BUCKET_BPA_DISABLED", "S3_VERSIONING_DISABLED",
        "S3_LOGGING_DISABLED",
    }  # fmt: skip
    assert by_id["S3_VERSIONING_DISABLED"].resource == "12 bucket(s)"
    assert "and 2 more" in by_id["S3_VERSIONING_DISABLED"].problem
    assert by_id["S3_LOGGING_DISABLED"].severity is Severity.INFO
    assert len(by_id["S3_VERSIONING_DISABLED"].evidence["buckets"]) == 12


def test_missing_encryption_configuration():
    responses = s3_account(["b1"], account_bpa=BPA_ON, get_bucket_encryption={
        "b1": error("ServerSideEncryptionConfigurationNotFoundError")})  # fmt: skip
    assert found(responses) == {("S3_ENCRYPTION_MISSING", Severity.LOW)}


def test_denied_bucket_calls_are_reported_as_incomplete_not_as_clean():
    responses = s3_account(
        ["b1", "b2"],
        account_bpa=BPA_ON,
        get_bucket_policy=dict.fromkeys(["b1", "b2"], error("AccessDenied")),
        get_bucket_versioning=dict.fromkeys(["b1", "b2"], error("AccessDenied")),
        get_bucket_encryption=dict.fromkeys(["b1", "b2"], error("AccessDenied")),
    )
    findings, statuses, _ = run(responses)
    assert findings == []
    s3 = next(s for s in statuses if s.name == "s3")
    assert s3.status == "completed"
    assert "incomplete" in s3.detail and "s3:GetBucketPolicy failed for 2 resource(s)" in s3.detail


# ------------------------------------------------------------------ network


def group(group_id, *rules):
    return {"GroupId": group_id, "GroupName": f"name-{group_id}", "IpPermissions": list(rules)}


def rule(low, high, cidr="0.0.0.0/0", protocol="tcp", v6=None):
    ranges = [{"CidrIp": cidr}] if cidr else []
    v6_ranges = [{"CidrIpv6": v6}] if v6 else []
    return {"IpProtocol": protocol, "FromPort": low, "ToPort": high, "IpRanges": ranges,
            "Ipv6Ranges": v6_ranges}  # fmt: skip


def network(groups, attached):
    return {
        ("ec2", "describe_security_groups"): {"SecurityGroups": groups},
        ("ec2", "describe_network_interfaces"): {
            "NetworkInterfaces": [{"Groups": [{"GroupId": g} for g in attached]}]
        },
    }


def test_security_group_exposure_is_classified_by_port_source_and_use():
    groups = [
        group("sg-ssh", rule(22, 22)),
        group("sg-db-v6", rule(5432, 5432, cidr=None, v6="::/0")),
        group("sg-range", rule(3000, 4000)),
        group("sg-all", {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}),
        group("sg-web", rule(443, 443), rule(80, 80)),
        group("sg-office", rule(22, 22, cidr="203.0.113.0/24")),
        group("sg-unused", rule(3389, 3389)),
        group("sg-unused-all", rule(0, 65535)),
        group("sg-udp", rule(22, 22, protocol="udp")),
    ]
    attached = ["sg-ssh", "sg-db-v6", "sg-range", "sg-all", "sg-web", "sg-office", "sg-udp"]
    findings, _, _ = run(network(groups, attached))
    result = {(f.resource.split("/")[-1], f.id, f.severity) for f in findings}
    assert result == {
        ("sg-ssh", "SG_OPEN_SENSITIVE_PORT", Severity.HIGH),
        ("sg-db-v6", "SG_OPEN_SENSITIVE_PORT", Severity.HIGH),
        ("sg-range", "SG_OPEN_SENSITIVE_PORT", Severity.HIGH),
        ("sg-all", "SG_OPEN_ALL_PORTS", Severity.CRITICAL),
        ("sg-unused", "SG_OPEN_SENSITIVE_PORT", Severity.LOW),
        ("sg-unused-all", "SG_OPEN_ALL_PORTS", Severity.MEDIUM),
    }
    ranged = next(f for f in findings if "sg-range" in f.resource)
    assert "3306 (MySQL)" in ranged.problem and "3389 (RDP)" in ranged.problem


def test_unknown_attachment_lowers_confidence_instead_of_assuming_unused():
    responses = network([group("sg-ssh", rule(22, 22))], [])
    responses[("ec2", "describe_network_interfaces")] = error("UnauthorizedOperation")
    findings, statuses, _ = run(responses)
    assert [(f.severity, f.confidence.value) for f in findings] == [(Severity.HIGH, "MEDIUM")]
    assert "incomplete" in next(s for s in statuses if s.name == "network").detail


# ------------------------------------------------------------------ CloudTrail


def trails(*items, status=None, selectors=None, public=False):
    return {
        ("cloudtrail", "describe_trails"): {"trailList": list(items)},
        ("cloudtrail", "get_trail_status"): status or {"IsLogging": True},
        ("cloudtrail", "get_event_selectors"): selectors
        or {"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]},
        ("s3", "get_bucket_policy_status"): {"PolicyStatus": {"IsPublic": public}},
    }


def test_cloudtrail_coverage():
    assert found(trails()) == {("CLOUDTRAIL_NO_TRAIL", Severity.HIGH)}
    assert found(trails(TRAIL, status={"IsLogging": False})) == {
        ("CLOUDTRAIL_NOT_LOGGING", Severity.HIGH)
    }
    single = {**TRAIL, "IsMultiRegionTrail": False}
    assert found(trails(single)) == {("CLOUDTRAIL_NOT_MULTI_REGION", Severity.MEDIUM)}
    assert found(trails(single), regions=("us-east-1", "eu-west-1")) >= {
        ("CLOUDTRAIL_NOT_LOGGING", Severity.HIGH)
    }
    no_validation = {**TRAIL, "LogFileValidationEnabled": False}
    assert found(trails(no_validation)) == {("CLOUDTRAIL_LOG_VALIDATION_DISABLED", Severity.LOW)}
    assert found(trails(TRAIL, public=True)) == {("CLOUDTRAIL_BUCKET_PUBLIC", Severity.CRITICAL)}


@pytest.mark.parametrize(
    ("selectors", "gap"),
    [
        ({"EventSelectors": [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}]}, True),
        ({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": False}]}, True),
        ({"AdvancedEventSelectors": [{"FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Management"]}]}]}, False),
        ({"AdvancedEventSelectors": [{"FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Management"]},
            {"Field": "readOnly", "Equals": ["false"]}]}]}, True),
        ({"AdvancedEventSelectors": [{"FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]}]}]}, True),
    ],
)  # fmt: skip
def test_management_event_gaps(selectors, gap):
    assert ("CLOUDTRAIL_MANAGEMENT_EVENTS_GAP" in ids(trails(TRAIL, selectors=selectors))) is gap


def test_unreadable_trail_status_is_not_reported_as_not_logging():
    responses = trails(TRAIL)
    responses[("cloudtrail", "get_trail_status")] = error("AccessDeniedException")
    findings, statuses, _ = run(responses)
    assert findings == []
    assert "incomplete" in next(s for s in statuses if s.name == "cloudtrail").detail


# ------------------------------------------------------------------ secrets, KMS, RDS


def test_secret_rotation_is_aggregated_and_skips_service_owned_secrets():
    secrets = [{"Name": "app/db"}, {"Name": "app/api"}, {"Name": "rotated", "RotationEnabled": True},
               {"Name": "rds!cluster", "OwningService": "rds"}]  # fmt: skip
    findings, _, _ = run({("secretsmanager", "list_secrets"): {"SecretList": secrets}})
    assert [(f.id, f.severity, f.evidence["secrets"]) for f in findings] == [
        ("SECRETS_ROTATION_DISABLED", Severity.LOW, ["app/api", "app/db"])
    ]
    assert "never rotates" in findings[0].remediation


def kms(policy, aliases=()):
    return {
        ("kms", "list_aliases"): {"Aliases": list(aliases)},
        ("kms", "list_keys"): {
            "Keys": [{"KeyId": "k-1", "KeyArn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/k-1"}]
        },
        ("kms", "get_key_policy"): {"Policy": json.dumps(policy)},
    }


def key_statement(principal, action="kms:Decrypt", condition=None):
    statement = {"Effect": "Allow", "Principal": principal, "Action": action, "Resource": "*"}
    if condition:
        statement["Condition"] = condition
    return statement


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (key_statement({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "kms:*"), set()),
        (key_statement("*"), {("KMS_KEY_PUBLIC", Severity.CRITICAL)}),
        (key_statement({"AWS": "*"}, condition={"StringEquals": {"kms:CallerAccount": ACCOUNT}}), set()),
        (key_statement({"AWS": "*"}, condition={"StringEquals": {
            "kms:ViaService": "s3.us-east-1.amazonaws.com"}}),
         {("KMS_KEY_WILDCARD_PRINCIPAL_CONDITIONED", Severity.MEDIUM)}),
        (key_statement({"AWS": "*"}, condition={"StringEquals": {
            "kms:ViaService": "s3.us-east-1.amazonaws.com", "kms:CallerAccount": ACCOUNT}}), set()),
        (key_statement({"AWS": "*"}, condition={"Bool": {"kms:GrantIsForAWSResource": "true"}}),
         {("KMS_KEY_WILDCARD_PRINCIPAL_CONDITIONED", Severity.MEDIUM)}),
        (key_statement({"AWS": f"arn:aws:iam::{OTHER}:root"}),
         {("KMS_KEY_CROSS_ACCOUNT", Severity.MEDIUM)}),
        (key_statement({"AWS": f"arn:aws:iam::{OTHER}:role/x"}, "kms:*"),
         {("KMS_KEY_CROSS_ACCOUNT", Severity.HIGH)}),
    ],
)  # fmt: skip
def test_kms_key_policies(statement, expected):
    assert found(kms(doc(statement))) == expected


def test_aws_managed_keys_are_not_fetched():
    responses = kms(
        doc(key_statement("*")), aliases=[{"AliasName": "alias/aws/s3", "TargetKeyId": "k-1"}]
    )
    findings, _, aws = run(responses)
    assert findings == []
    assert not [c for c in aws.calls if c[1] == "get_key_policy"]


def database(name, public=False, encrypted=True, groups=("sg-db",)):
    return {"DBInstanceIdentifier": name, "DBInstanceArn": f"arn:aws:rds:us-east-1:{ACCOUNT}:db:{name}",
            "Engine": "postgres", "PubliclyAccessible": public, "StorageEncrypted": encrypted,
            "Endpoint": {"Port": 5432},
            "VpcSecurityGroups": [{"VpcSecurityGroupId": g} for g in groups]}  # fmt: skip


def rds(instances, groups=()):
    return {
        ("rds", "describe_db_instances"): {"DBInstances": instances},
        ("ec2", "describe_security_groups"): lambda region=None, GroupIds=None, **_: {
            "SecurityGroups": [g for g in groups if GroupIds is None or g["GroupId"] in GroupIds]
            if GroupIds
            else []
        },
    }


def test_rds_exposure_combines_public_flag_and_security_group():
    open_group = group("sg-db", rule(5432, 5432))
    closed_group = group("sg-db", rule(5432, 5432, cidr="10.0.0.0/8"))
    other_port = group("sg-db", rule(22, 22))
    assert found(rds([database("d", public=True)], [open_group])) == {
        ("RDS_PUBLIC_OPEN", Severity.CRITICAL)
    }
    assert found(rds([database("d", public=True)], [closed_group])) == {
        ("RDS_PUBLICLY_ACCESSIBLE", Severity.MEDIUM)
    }
    assert found(rds([database("d", public=True)], [other_port])) == {
        ("RDS_PUBLICLY_ACCESSIBLE", Severity.MEDIUM)
    }
    assert found(rds([database("d")], [open_group])) == set()


def test_unencrypted_database_severity_depends_on_exposure_and_environment():
    private = rds([database("d", encrypted=False)])
    assert found(private) == {("RDS_UNENCRYPTED", Severity.MEDIUM)}
    assert found(private, {"environment": "staging"}) == {("RDS_UNENCRYPTED", Severity.LOW)}
    exposed = rds([database("d", public=True, encrypted=False)], [group("sg-db")])
    assert ("RDS_UNENCRYPTED", Severity.HIGH) in found(exposed)


# ------------------------------------------------------------------ runner


def test_one_denied_and_one_broken_analyzer_do_not_stop_the_audit():
    findings, statuses, _ = run({
        ("iam", "get_account_authorization_details"): error("AccessDenied"),
        ("rds", "describe_db_instances"): error("InternalFailure"),
        ("iam", "get_account_summary"): {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
        },
    })  # fmt: skip
    by_name = {s.name: s for s in statuses}
    assert by_name["iam_policies"].status == "skipped"
    assert by_name["iam_policies"].detail == "missing permission iam:GetAccountAuthorizationDetails"
    assert by_name["iam_roles"].status == "skipped"
    assert by_name["rds"].status == "failed" and "InternalFailure" in by_name["rds"].detail
    assert sum(s.status == "completed" for s in statuses) == 7
    assert {f.id for f in findings} == {"IAM_ROOT_MFA_DISABLED"}


def test_shared_iam_data_is_fetched_once():
    _, _, aws = run()
    operations = [c[1] for c in aws.calls]
    assert operations.count("get_account_authorization_details") == 1
    assert operations.count("get_credential_report") == 1


def test_regional_analyzers_survive_an_unavailable_region():
    def groups(region=None, **_):
        if region == "me-south-1":
            raise error("AuthFailure")
        return {"SecurityGroups": [group("sg-ssh", rule(22, 22))]}

    findings, statuses, _ = run(
        {("ec2", "describe_security_groups"): groups}, regions=("us-east-1", "me-south-1")
    )
    network_status = next(s for s in statuses if s.name == "network")
    assert network_status.status == "completed"
    assert "me-south-1: Region not available" in network_status.detail
    assert [f.resource for f in findings if f.id == "SG_OPEN_SENSITIVE_PORT"] == [
        f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-ssh"
    ]


def test_expired_credentials_abort_with_an_auth_error():
    with pytest.raises(AwsAuthError, match="expired"):
        run({("s3", "list_buckets"): error("ExpiredToken")})


def test_analyzers_can_be_selected_and_unknown_names_are_rejected():
    _, statuses, aws = run(config={"enabled_analyzers": ["s3"]})
    assert {s.name for s in statuses if s.status == "completed"} == {"s3"}
    assert all(s.detail == "disabled in configuration" for s in statuses if s.name != "s3")
    assert {c[0] for c in aws.calls} == {"s3", "s3control"}
    with pytest.raises(ConfigError, match="Unknown analyzer 'ec3'"):
        run(config={"enabled_analyzers": ["ec3"]})


def test_only_allow_listed_read_only_operations_can_be_called():
    provider = AWSClientProvider()
    provider.client = FakeAWS({}).client
    ctx = AuditContext(provider, ACCOUNT, ["us-east-1"], Config())
    with pytest.raises(RuntimeError, match="not an allow-listed"):
        ctx.call("iam", "delete_user", UserName="x")
    for (_, operation), permission in OPERATIONS.items():
        assert operation.startswith(("get_", "list_", "describe_")) or (
            operation == "generate_credential_report"
        )
        assert permission.split(":")[1].startswith(("Get", "List", "Describe", "Generate"))


def test_permission_manifest_matches_the_allow_list():
    manifest = json.loads((REPO / "permissions" / "audit-readonly-policy.json").read_text())
    assert manifest == permission_manifest()
    actions = manifest["Statement"][0]["Action"]
    assert "iam:GetAccountAuthorizationDetails" in actions and "sts:GetCallerIdentity" in actions
    assert not [a for a in actions if "*" in a]


def test_paginated_operations_are_followed_to_the_end():
    client = boto3.client("iam", region_name="us-east-1")
    stub = Stubber(client)
    user_page = {"UserName": "u", "Arn": f"arn:aws:iam::{ACCOUNT}:user/u", "Path": "/",
                 "UserId": "AIDAEXAMPLEEXAMPLE00", "CreateDate": NOW}  # fmt: skip
    stub.add_response("get_account_authorization_details",
                      {"UserDetailList": [user_page], "IsTruncated": True, "Marker": "next"})  # fmt: skip
    stub.add_response("get_account_authorization_details",
                      {"UserDetailList": [{**user_page, "UserName": "v"}], "IsTruncated": False})  # fmt: skip
    stub.activate()
    provider = AWSClientProvider()
    provider.client = lambda service, region=None: client
    ctx = AuditContext(provider, ACCOUNT, ["us-east-1"], Config())
    users = ctx.pages("iam", "get_account_authorization_details", "UserDetailList")
    assert [u["UserName"] for u in users] == ["u", "v"]
    stub.assert_no_pending_responses()


def test_region_resolution():
    provider = AWSClientProvider()
    provider.client = FakeAWS({
        ("ec2", "describe_regions"): {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "ap-south-1"}]}
    }).client  # fmt: skip
    assert resolve_regions(provider, Config(), None, True) == ["ap-south-1", "us-east-1"]
    assert resolve_regions(provider, Config(), "eu-west-1", False) == ["eu-west-1"]
    configured = Config.model_validate({"audit": {"regions": ["us-west-2", "us-east-2"]}})
    assert resolve_regions(provider, configured, None, False) == ["us-west-2", "us-east-2"]
    with pytest.raises(ConfigError, match="No AWS region"):
        resolve_regions(provider, Config(), None, False)


# ------------------------------------------------------------------ configuration and scoring

ROOT_PROBLEMS = {
    ("iam", "get_account_summary"): {
        "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}
    }
}


def test_ignored_findings_resources_and_severity_overrides():
    findings, _, _ = run({**ROOT_PROBLEMS, **network([group("sg-1", rule(22, 22))], ["sg-1"])})
    settings = Config.model_validate({"audit": {
        "ignored_findings": ["IAM_ROOT_ACCESS_KEYS"],
        "ignored_resources": ["arn:aws:ec2:*:security-group/sg-1"],
        "severity_overrides": {"IAM_ROOT_MFA_DISABLED": "low"},
    }})  # fmt: skip
    kept, ignored = apply_config(findings, settings)
    assert [(f.id, f.severity) for f in kept] == [("IAM_ROOT_MFA_DISABLED", Severity.LOW)]
    assert ignored == 2


def test_scoring_model():
    findings, _, _ = run(ROOT_PROBLEMS)
    assert score(findings) == 50  # two CRITICAL findings, 25 points each
    assert scores(findings)["least_privilege"] == 100  # neither is a least-privilege finding
    many = run(network([group(f"sg-{i}", rule(22, 22)) for i in range(30)],
                       [f"sg-{i}" for i in range(30)]))[0]  # fmt: skip
    assert len(many) == 30 and score(many) == 80  # one repeated HIGH rule costs at most 2 x 10
    admin = run(with_details(policies=[managed("admin", doc(allow("*")))]))[0]
    assert scores(admin) == {"security": 90, "least_privilege": 90}
    assert score([]) == 100


def test_every_rule_is_actionable():
    from fmaws.audit.findings import RULES, make

    for rule_id in RULES:
        finding = make(rule_id, "resource", "problem")
        assert finding.title and finding.why_it_matters and finding.remediation
        assert finding.documentation_url.startswith("https://")
        assert finding.is_auto_fixable is False


# ------------------------------------------------------------------ reports


def sample_report():
    findings, statuses, _ = run({
        **ROOT_PROBLEMS,
        ("rds", "describe_db_instances"): error("AccessDenied"),
        **network([group("sg-1", rule(22, 22))], ["sg-1"]),
    })  # fmt: skip
    kept, ignored = apply_config(findings, Config())
    return Report(command="audit", findings=kept, analyzers=statuses, scores=scores(kept),
                  ignored=ignored, context={"account": ACCOUNT, "region": "us-east-1"})  # fmt: skip


def test_console_report():
    text = render(sample_report(), "console")
    assert "AWS Security Score: 40/100" in text
    assert "Least Privilege Score: 100/100" in text
    assert "Completed: 9 analyzers" in text and "Skipped: 1" in text and "Failed: 0" in text
    assert "rds: skipped, us-east-1: missing permission rds:DescribeDBInstances" in text
    assert "CRITICAL  IAM" in text and "Root user has access keys" in text
    assert "Problem:" in text and "Fix:" in text and "Confidence: HIGH" in text
    assert "Account: ********3333" in text
    assert text.index("CRITICAL  IAM") < text.index("HIGH  EC2")


def test_json_and_markdown_reports():
    data = json.loads(render(sample_report(), "json"))
    assert data["scores"] == {"security": 40, "least_privilege": 100}
    assert data["summary"] == {
        "critical": 2,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
        "ignored": 0,
    }
    assert {a["name"]: a["status"] for a in data["analyzers"]}["rds"] == "skipped"
    assert data["findings"][0]["severity"] == "CRITICAL"
    markdown = render(sample_report(), "markdown")
    assert markdown.startswith("# fmaws audit report")
    assert "AWS Security Score: **40/100**" in markdown and "### CRITICAL:" in markdown


def test_sarif_report_is_valid_for_code_scanning():
    sarif = json.loads(render(sample_report(), "sarif"))
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    run_ = sarif["runs"][0]
    assert run_["tool"]["driver"]["name"] == "fmaws"
    rules = {r["id"]: r for r in run_["tool"]["driver"]["rules"]}
    assert set(rules) == {"IAM_ROOT_MFA_DISABLED", "IAM_ROOT_ACCESS_KEYS", "SG_OPEN_SENSITIVE_PORT"}
    assert rules["IAM_ROOT_ACCESS_KEYS"]["properties"]["security-severity"] == "9.5"
    assert rules["SG_OPEN_SENSITIVE_PORT"]["defaultConfiguration"]["level"] == "error"
    assert rules["SG_OPEN_SENSITIVE_PORT"]["helpUri"].startswith("https://")
    for result in run_["results"]:
        assert result["ruleId"] in rules and result["message"]["text"]
        location = result["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "fmaws.yaml"
        assert location["physicalLocation"]["region"]["startLine"] == 1
        assert len(result["partialFingerprints"]["fmawsFindingHash/v1"]) == 64


# ------------------------------------------------------------------ CLI


@pytest.fixture
def cli(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def invoke(overrides=None, *args, config=None):
        aws = FakeAWS({**healthy(), **(overrides or {})})
        monkeypatch.setattr(AWSClientProvider, "client", lambda self, s, r=None: aws.client(s, r))
        monkeypatch.setattr(
            AWSClientProvider, "identity",
            lambda self: {"account": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:user/dev"},
        )  # fmt: skip
        (tmp_path / "fmaws.yaml").write_text(
            json.dumps({"audit": {"concurrency": 1, **(config or {})}})
        )
        return runner.invoke(app, ["audit", "--region", "us-east-1", *args])

    return invoke


SSH_OPEN = network([group("sg-1", rule(22, 22))], ["sg-1"])


def test_cli_exit_codes_follow_the_threshold(cli):
    assert cli().exit_code == 0
    assert cli(SSH_OPEN).exit_code == 0  # findings alone never fail without a threshold
    assert cli(SSH_OPEN, "--fail-on", "critical").exit_code == 0
    assert cli(SSH_OPEN, "--fail-on", "high").exit_code == 1
    assert cli(SSH_OPEN, "--fail-on", "low").exit_code == 1
    assert cli(ROOT_PROBLEMS, "--fail-on", "critical").exit_code == 1


def test_cli_threshold_from_configuration_and_environment(cli):
    assert cli(SSH_OPEN, config={"fail_on": ["critical", "high"]}).exit_code == 1
    assert cli(SSH_OPEN, config={"fail_on": "critical"}).exit_code == 0
    by_environment = {
        "production": {"fail_on": ["high"]},
        "non_production": {"fail_on": ["critical"]},
    }
    assert cli(SSH_OPEN, config=by_environment).exit_code == 1
    assert cli(SSH_OPEN, config={**by_environment, "environment": "staging"}).exit_code == 0
    # The command line wins over configuration.
    assert cli(SSH_OPEN, "--fail-on", "critical", config={"fail_on": ["high"]}).exit_code == 0


def test_cli_gate_does_not_pass_on_an_incomplete_audit(cli):
    denied = {("rds", "describe_db_instances"): error("AccessDenied")}
    assert cli(denied).exit_code == 0
    gated = cli(denied, "--fail-on", "high")
    assert gated.exit_code == 2 and "audit is incomplete (rds)" in gated.output
    assert cli(denied, "--fail-on", "high", "--allow-partial").exit_code == 0
    # Findings still decide first: an incomplete audit with a violation is exit 1.
    assert cli({**denied, **SSH_OPEN}, "--fail-on", "high").exit_code == 1
    disabled = cli(None, "--fail-on", "high", config={"enabled_analyzers": ["s3"]})
    assert disabled.exit_code == 0  # analyzers disabled on purpose are not "incomplete"


def test_cli_exits_3_when_nothing_could_be_audited(cli):
    everything_denied = {key: error("AccessDenied") for key in healthy()}
    result = cli(everything_denied)
    assert result.exit_code == 3
    assert "Completed: 0 analyzers" in result.output
    assert "audit-readonly-policy.json" in result.output


def test_cli_formats(cli):
    console = cli(SSH_OPEN)
    assert "AWS Security Score: 90/100" in console.output and "HIGH  EC2" in console.output
    assert json.loads(cli(SSH_OPEN, "--format", "json").output)["findings"][0]["id"] == (
        "SG_OPEN_SENSITIVE_PORT"
    )
    assert json.loads(cli(SSH_OPEN, "--format", "sarif").output)["runs"][0]["results"]
    assert cli(SSH_OPEN, "--format", "markdown").output.startswith("# fmaws audit report")


def test_cli_without_credentials_exits_3(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    result = runner.invoke(app, ["audit", "--region", "us-east-1"])
    assert result.exit_code == 3 and "No usable AWS credentials" in result.output


# ------------------------------------------------------------------ policy evaluation hardening


@pytest.mark.parametrize(
    "condition",
    [
        {"ForAllValues:StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
        {"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1a2b3c"}},
        {"IpAddress": {"aws:SourceIp": ["0.0.0.0/1", "128.0.0.0/1"]}},
        {"IpAddress": {"aws:SourceIp": "not-an-ip"}},
        {"StringLike": {"aws:SourceVpce": "vpce-*"}},
        {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}},
        {"ArnEquals": {"aws:SourceArn": "arn:aws:*"}},
        {"StringLike": {"aws:PrincipalOrgID": "o-*"}},
        {"StringEquals": {"aws:SourceVpce": ["vpce-1a2b3c", ""]}},
        # Every range is "small", together they are the whole IPv4 internet.
        {"IpAddress": {"aws:SourceIp": [f"{i}.0.0.0/8" for i in range(256)]}},
        {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "11.0.0.0/8"]}},
        # The 12 digits are a role name, not the account field.
        {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/123456789012"}},
        {"StringLike": {"aws:PrincipalAccount": "1111222233*"}},
        {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}},
    ],
)
def test_conditions_that_do_not_pin_the_caller_do_not_hide_a_public_bucket(condition):
    policy = bucket_policy(public("s3:GetObject", "b1", Condition=condition))
    result = ids(s3_account(["b1"], get_bucket_policy={"b1": policy}))
    assert "S3_WILDCARD_PRINCIPAL_CONDITIONED" in result or "S3_PUBLIC_READ" in result


@pytest.mark.parametrize(
    "condition",
    [
        {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/*"}},
        {"ForAnyValue:StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
        {"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "2001:db8::/32"]}},
    ],
)
def test_conditions_that_pin_the_caller_are_accepted(condition):
    policy = bucket_policy(public("s3:GetObject", "b1", Condition=condition))
    result = ids(s3_account(["b1"], account_bpa=BPA_ON, get_bucket_policy={"b1": policy}))
    assert result == set()


@pytest.mark.parametrize(
    "action", ["s3:GetObjectVersion", "s3:GetBucketAcl", "s3:ListBucketVersions", "s3:Get*"]
)
def test_any_public_s3_action_is_reported(action):
    policy = bucket_policy(public(action, "b1"))
    assert "S3_PUBLIC_READ" in ids(s3_account(["b1"], get_bucket_policy={"b1": policy}))


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("s3:DeleteObjectVersion", "S3_PUBLIC_DELETE"),
        ("s3:PutBucketWebsite", "S3_PUBLIC_WRITE"),
        ("s3:PutLifecycleConfiguration", "S3_PUBLIC_WRITE"),
    ],
)
def test_more_public_write_and_delete_actions(action, expected):
    policy = bucket_policy(public(action, "b1"))
    assert expected in ids(s3_account(["b1"], get_bucket_policy={"b1": policy}))


def test_not_principal_is_public():
    statement = {"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/x"},
                 "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*"}  # fmt: skip
    assert "S3_PUBLIC_READ" in ids(
        s3_account(["b1"], get_bucket_policy={"b1": bucket_policy(statement)})
    )
    trust_everyone_else = doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                               "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/x"}})  # fmt: skip
    assert "IAM_ROLE_TRUST_PUBLIC" in ids(with_details(roles=[role("r", trust_everyone_else)]))


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        '{"Statement": [{"Effect": "Deny", "Effect": "Allow", "Principal": "*", '
        '"Action": "s3:GetObject", "Resource": "*"}]}',
        "[]",
        '{"Statement": ["x"]}',
    ],
)
def test_unreadable_policies_make_the_analyzer_incomplete_instead_of_clean(raw):
    responses = s3_account(["b1"], account_bpa=BPA_ON, get_bucket_policy={"b1": {"Policy": raw}})
    findings, statuses, _ = run(responses)
    assert findings == []
    assert (
        "reading a policy failed for 1 resource(s)"
        in next(s for s in statuses if s.name == "s3").detail
    )


def test_external_accounts_named_through_sts_arns_or_conditions():
    assumed = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*",
               "Principal": {"AWS": f"arn:aws:sts::{OTHER}:assumed-role/app/session"}}  # fmt: skip
    by_condition = public("s3:GetObject", "b1", Condition={
        "StringEquals": {"aws:PrincipalAccount": OTHER}})  # fmt: skip
    for statement in (assumed, by_condition):
        responses = s3_account(["b1"], account_bpa=BPA_ON,
                               get_bucket_policy={"b1": bucket_policy(statement)})  # fmt: skip
        assert ids(responses) == {"S3_CROSS_ACCOUNT_ACCESS"}
    key = key_statement({"AWS": "*"}, condition={"StringEquals": {"kms:CallerAccount": OTHER}})
    assert ids(kms(doc(key))) == {"KMS_KEY_CROSS_ACCOUNT"}


@pytest.mark.parametrize(
    ("subject", "unrestricted"),
    [
        ("repo:*", True),
        ("repo:acme*", True),
        ("*:ref:refs/heads/main", True),
        ("repo:acme/*", False),
        ("repo:acme/shop:ref:refs/heads/main", False),
        ("system:serviceaccount:prod:*", False),
    ],
)
def test_oidc_subject_must_name_an_owner(subject, unrestricted):
    provider = {
        "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    }
    document = trust(provider, {"StringLike": {"token.actions.githubusercontent.com:sub": subject}},
                     "sts:AssumeRoleWithWebIdentity")  # fmt: skip
    result = ids(with_details(roles=[role("ci", document)]))
    assert ("IAM_ROLE_TRUST_OIDC_UNRESTRICTED" in result) is unrestricted


def test_for_all_values_does_not_restrict_an_oidc_subject():
    provider = {
        "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    }
    document = trust(provider, {"ForAllValues:StringEquals": {
        "token.actions.githubusercontent.com:sub": "repo:acme/shop:ref:refs/heads/main"}},
        "sts:AssumeRoleWithWebIdentity")  # fmt: skip
    assert "IAM_ROLE_TRUST_OIDC_UNRESTRICTED" in ids(with_details(roles=[role("ci", document)]))


def test_account_is_read_from_the_account_field_only():
    from fmaws.audit.policies import account_of

    assert account_of(OTHER) == OTHER
    assert account_of(f"arn:aws:iam::{OTHER}:role/app") == OTHER
    assert account_of(f"arn:aws:sts::{OTHER}:assumed-role/app/session") == OTHER
    assert account_of(f"arn:aws:iam::*:role/{OTHER}") is None
    assert account_of(f"arn:aws:iam::aws:policy/{OTHER}") is None
    assert account_of("*") is None
    spoof = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*",
             "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/{OTHER}"}}  # fmt: skip
    responses = s3_account(
        ["b1"], account_bpa=BPA_ON, get_bucket_policy={"b1": bucket_policy(spoof)}
    )
    assert ids(responses) == set()


def test_a_condition_lowers_but_never_hides_wildcard_data_access():
    condition = {"Bool": {"aws:SecureTransport": "true"}}
    policy = doc(
        allow("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{ACCOUNT}:secret:*",
              Condition=condition),
        allow("dynamodb:GetItem", f"arn:aws:dynamodb:*:{ACCOUNT}:table/*", Condition=condition),
    )  # fmt: skip
    result = found(with_details(policies=[managed("p", policy)]))
    assert ("IAM_SECRETS_WILDCARD_ACCESS", Severity.MEDIUM) in result
    assert ("IAM_DYNAMODB_WILDCARD_ACCESS", Severity.LOW) in result


def test_every_secret_of_one_region_is_still_every_secret():
    policy = doc(allow("secretsmanager:GetSecretValue",
                       f"arn:aws:secretsmanager:eu-west-1:{ACCOUNT}:secret:*"))  # fmt: skip
    assert ("IAM_SECRETS_WILDCARD_ACCESS", Severity.HIGH) in found(
        with_details(policies=[managed("p", policy)])
    )


def test_incomplete_flag_is_explicit_and_not_set_for_disabled_analyzers():
    _, statuses, _ = run({("rds", "describe_db_instances"): error("AccessDenied")},
                         config={"enabled_analyzers": ["rds", "s3"]})  # fmt: skip
    by_name = {s.name: s for s in statuses}
    assert by_name["rds"].incomplete and not by_name["s3"].incomplete
    assert not by_name["kms"].incomplete  # disabled on purpose is not incomplete
    assert by_name["rds"].model_dump()["incomplete"] is True


def test_external_id_alone_does_not_make_a_wildcard_trust_private():
    document = trust({"AWS": "*"}, {"StringEquals": {"sts:ExternalId": "s3cr3t"}})
    assert found(with_details(roles=[role("r", document)])) == {
        ("IAM_ROLE_TRUST_PUBLIC", Severity.MEDIUM)
    }


def test_unreadable_block_public_access_is_unknown_not_disabled():
    responses = s3_account(["b1"], account_bpa=error("AccessDenied"),
                           get_public_access_block={"b1": error("AccessDenied")})  # fmt: skip
    findings, statuses, _ = run(responses)
    assert findings == []
    detail = next(s for s in statuses if s.name == "s3").detail
    assert "s3:GetAccountPublicAccessBlock failed" in detail
    assert "s3:GetBucketPublicAccessBlock failed" in detail


def test_sarif_marks_an_incomplete_audit_as_unsuccessful():
    invocation = json.loads(render(sample_report(), "sarif"))["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert "rds: skipped" in invocation["toolExecutionNotifications"][0]["message"]["text"]
    findings, statuses, _ = run()
    clean = Report(command="audit", findings=findings, analyzers=statuses)
    assert json.loads(render(clean, "sarif"))["runs"][0]["invocations"][0] == {
        "executionSuccessful": True,
        "toolExecutionNotifications": [],
    }


def test_credential_report_that_never_completes_fails_the_analyzer(monkeypatch):
    from fmaws.audit import iam

    monkeypatch.setattr(iam.time, "sleep", lambda _: None)
    _, statuses, _ = run({("iam", "generate_credential_report"): {"State": "STARTED"}})
    by_name = {s.name: s for s in statuses}
    assert by_name["iam_credentials"].status == "failed"
    assert by_name["iam_credentials"].incomplete
