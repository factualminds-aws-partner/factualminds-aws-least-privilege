import json

import pytest

from fmaws.models.finding import Severity
from fmaws.validators.local import load_policy_file, validate_policy_document


def doc(*statements, version="2012-10-17"):
    return {"Version": version, "Statement": list(statements)}


def allow(action, resource="arn:aws:s3:::bucket/key", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def ids(document, **kwargs):
    return {f.id: f.severity for f in validate_policy_document(document, **kwargs)}


def test_clean_policy_has_no_findings():
    assert ids(doc(allow(["s3:GetObject", "s3:PutObject"]))) == {}


def test_full_admin_is_critical():
    assert ids(doc(allow("*", "*"))) == {"POLICY_FULL_ADMIN": Severity.CRITICAL}


def test_action_wildcard_on_specific_resource_is_high():
    assert ids(doc(allow("*"))) == {"POLICY_ACTION_WILDCARD": Severity.HIGH}


def test_service_wildcard_severity_depends_on_service_and_threshold():
    assert ids(doc(allow("s3:*")))["POLICY_SERVICE_WILDCARD"] is Severity.MEDIUM
    assert (
        ids(doc(allow("iam:*", "arn:aws:iam::111122223333:role/x")))["POLICY_SERVICE_WILDCARD"]
        is Severity.HIGH
    )
    assert (
        ids(doc(allow("s3:*")), wildcard_severity=Severity.HIGH)["POLICY_SERVICE_WILDCARD"]
        is Severity.HIGH
    )


def test_partial_wildcard_severity_depends_on_service_and_scope():
    assert ids(doc(allow("s3:Get*"))) == {"POLICY_PARTIAL_WILDCARD": Severity.LOW}
    assert ids(doc(allow("s3:Get*", "*"))) == {"POLICY_PARTIAL_WILDCARD": Severity.MEDIUM}
    assert ids(doc(allow("iam:Get*", "arn:aws:iam::111122223333:role/app"))) == {
        "POLICY_PARTIAL_WILDCARD": Severity.HIGH
    }


def test_service_wildcard_on_every_resource_is_an_error():
    assert ids(doc(allow("s3:*", "*"))) == {"POLICY_SERVICE_WILDCARD": Severity.HIGH}
    assert ids(doc(allow("ec2:*", "*")), wildcard_severity=Severity.INFO) == {
        "POLICY_SERVICE_WILDCARD": Severity.HIGH
    }


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        ("iam:AttachRolePolicy", "*"),
        ("iam:putuserpolicy", "arn:aws:iam::*:user/*"),
        ("iam:CreatePolicyVersion", "arn:aws:iam::111122223333:policy/*"),
        ("sts:AssumeRole", "arn:aws:iam::111122223333:role/*"),
        ("iam:CreateAccessKey", "*"),
    ],
)
def test_privilege_escalation_on_arbitrary_principals(action, resource):
    assert ids(doc(allow(action, resource)))["POLICY_PRIVILEGE_ESCALATION"] is Severity.HIGH


def test_escalation_action_on_one_named_principal_is_not_flagged():
    assert ids(doc(allow("sts:AssumeRole", "arn:aws:iam::111122223333:role/deployer"))) == {}


def test_not_resource_does_not_hide_what_is_granted():
    def not_resource(action):
        return {"Effect": "Allow", "Action": action, "NotResource": "arn:aws:s3:::one-bucket/*"}

    assert ids(doc(not_resource("iam:PassRole")))["POLICY_PASSROLE_BROAD"] is Severity.HIGH
    assert ids(doc(not_resource("*")))["POLICY_FULL_ADMIN"] is Severity.CRITICAL
    escalation = ids(doc(not_resource("iam:AttachRolePolicy")))
    assert escalation["POLICY_PRIVILEGE_ESCALATION"] is Severity.HIGH


def test_resource_and_not_resource_together_are_invalid():
    both = allow("s3:GetObject", NotResource="arn:aws:s3:::b/*")
    assert ids(doc(both)) == {"POLICY_INVALID_STRUCTURE": Severity.HIGH}
    principals = allow("s3:GetObject", Principal="*", NotPrincipal="*")
    assert ids(doc(principals)) == {"POLICY_INVALID_STRUCTURE": Severity.HIGH}


@pytest.mark.parametrize(
    "condition",
    [
        {"StringLike": {"aws:PrincipalArn": "*"}},
        {"ArnLike": {"aws:PrincipalArn": ["*", "**"]}},
        {"StringLikeIfExists": {"aws:userid": "*"}},
    ],
)
def test_always_true_conditions_do_not_lower_severity(condition):
    assert ids(doc(allow("s3:GetObject", Principal="*", Condition=condition))) == {
        "POLICY_PUBLIC_PRINCIPAL": Severity.CRITICAL
    }
    assert ids(doc(allow("*", "*", Condition=condition))) == {
        "POLICY_FULL_ADMIN": Severity.CRITICAL
    }


def test_resource_wildcard_distinguishes_scopable_required_and_unknown():
    assert ids(doc(allow("s3:GetObject", "*"))) == {"POLICY_RESOURCE_WILDCARD": Severity.MEDIUM}
    assert ids(doc(allow(["dynamodb:ListTables", "sqs:ListQueues"], "*"))) == {}
    assert ids(doc(allow("ec2:DescribeInstances", "*"))) == {
        "POLICY_RESOURCE_WILDCARD_UNKNOWN": Severity.LOW
    }


def test_broad_passrole():
    assert ids(doc(allow("iam:PassRole", "*")))["POLICY_PASSROLE_BROAD"] is Severity.HIGH
    assert "POLICY_PASSROLE_BROAD" not in ids(
        doc(allow("iam:PassRole", "arn:aws:iam::111122223333:role/app"))
    )


def test_not_action_and_not_resource_with_allow():
    not_action = {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    assert ids(doc(not_action)) == {"POLICY_NOT_ACTION_ALLOW": Severity.HIGH}
    not_resource = {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::b/*"}
    assert ids(doc(not_resource)) == {
        "POLICY_NOT_RESOURCE_ALLOW": Severity.MEDIUM,
        "POLICY_RESOURCE_WILDCARD": Severity.MEDIUM,
    }


def test_deny_statements_are_not_flagged_for_breadth():
    assert ids(doc({"Effect": "Deny", "Action": "*", "Resource": "*"})) == {}


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*"]}, {"AWS": ["x", "*"]}])
def test_public_principal_in_every_form(principal):
    statement = allow("s3:GetObject", Principal=principal)
    assert ids(doc(statement)) == {"POLICY_PUBLIC_PRINCIPAL": Severity.CRITICAL}


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": {"aws:PrincipalOrgID": "o-1"}},
        {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:*"}},
    ],
)
def test_conditioned_public_principal_is_downgraded_never_silenced(condition):
    statement = allow("s3:GetObject", Principal="*", Condition=condition)
    assert ids(doc(statement)) == {"POLICY_PUBLIC_PRINCIPAL": Severity.MEDIUM}


def test_empty_or_malformed_condition_does_not_count_as_a_restriction():
    assert (
        ids(doc(allow("s3:GetObject", Principal="*", Condition={})))["POLICY_PUBLIC_PRINCIPAL"]
        is Severity.CRITICAL
    )
    malformed = ids(doc(allow("*", "*", Condition=["x"])))
    assert malformed["POLICY_FULL_ADMIN"] is Severity.CRITICAL


def test_not_principal_with_allow():
    statement = allow("s3:GetObject", NotPrincipal={"AWS": "arn:aws:iam::111122223333:root"})
    assert ids(doc(statement)) == {"POLICY_PUBLIC_PRINCIPAL": Severity.HIGH}


@pytest.mark.parametrize(
    "condition",
    [
        {"StringNotEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
        {"StringEqualsIfExists": {"iam:PassedToService": "ec2.amazonaws.com"}},
        {"StringLike": {"iam:PassedToService": "*"}},
        {"StringEquals": {"aws:RequestedRegion": "iam:PassedToService"}},
        {"StringEquals": {"iam:PassedToService": []}},
    ],
)
def test_passrole_conditions_that_do_not_restrict_are_still_flagged(condition):
    statement = allow("iam:PassRole", "*", Condition=condition)
    assert ids(doc(statement))["POLICY_PASSROLE_BROAD"] is Severity.HIGH


@pytest.mark.parametrize("key", ["condition", "Conditions", "Resources", "Actions", "effect"])
def test_unknown_statement_elements_are_rejected(key):
    assert (
        ids(doc(allow("s3:GetObject", **{key: "x"})))["POLICY_INVALID_STRUCTURE"] is Severity.HIGH
    )


def test_unknown_top_level_element_and_empty_statement():
    extra = {"Version": "2012-10-17", "Statement": [allow("s3:GetObject")], "statement": []}
    assert ids(extra) == {"POLICY_INVALID_STRUCTURE": Severity.HIGH}
    assert ids(doc()) == {"POLICY_INVALID_STRUCTURE": Severity.HIGH}


@pytest.mark.parametrize("resource", ["arn:aws:s3:::*/*", "arn:aws:s3:::**", "arn:aws:s3:::*?*"])
def test_equivalent_spellings_of_every_resource_in_a_service(resource):
    assert ids(doc(allow("s3:GetObject", resource))) == {"POLICY_BROAD_RESOURCE": Severity.MEDIUM}


@pytest.mark.parametrize(
    "resource",
    [
        "arn:aws:dynamodb:us-east-1:111122223333:table/*",
        "arn:aws:secretsmanager:us-east-1:111122223333:secret:*",
        "arn:aws:lambda:us-east-1:111122223333:function:*",
    ],
)
def test_type_wide_wildcards_are_flagged_unless_conditioned(resource):
    assert ids(doc(allow("dynamodb:GetItem", resource))) == {
        "POLICY_BROAD_RESOURCE": Severity.MEDIUM
    }
    scoped = allow(
        "dynamodb:GetItem", resource, Condition={"StringEquals": {"aws:ResourceTag/app": "x"}}
    )
    assert ids(doc(scoped)) == {"POLICY_BROAD_RESOURCE": Severity.LOW}


def test_kms_alias_pattern_is_accepted_only_with_a_pinned_alias():
    key = "arn:aws:kms:us-east-1:111122223333:key/*"
    pinned = {"ForAnyValue:StringEquals": {"kms:ResourceAliases": ["alias/app"]}}
    assert ids(doc(allow("kms:Decrypt", key, Condition=pinned))) == {}
    loose = {"ForAnyValue:StringLike": {"kms:ResourceAliases": ["alias/*"]}}
    assert ids(doc(allow("kms:Decrypt", key, Condition=loose))) == {
        "POLICY_BROAD_RESOURCE": Severity.LOW
    }
    assert ids(doc(allow("kms:Decrypt", key))) == {"POLICY_BROAD_RESOURCE": Severity.MEDIUM}


def test_size_counts_whitespace_inside_strings(tmp_path):
    padded = doc(allow("s3:GetObject", Condition={"StringEquals": {"aws:x": " " * 6200}}))
    assert ids(padded) == {"POLICY_SIZE": Severity.MEDIUM}


def test_nan_and_infinity_are_not_json(tmp_path):
    path = tmp_path / "nan.json"
    path.write_text('{"Version": NaN, "Statement": []}')
    assert load_policy_file(path)[1][0].id == "POLICY_INVALID_JSON"


def test_broad_and_account_wildcard_resources():
    assert ids(doc(allow("s3:GetObject", "arn:aws:s3:::*"))) == {
        "POLICY_BROAD_RESOURCE": Severity.MEDIUM
    }
    assert ids(doc(allow("sqs:SendMessage", "arn:aws:sqs:us-east-1:*:orders"))) == {
        "POLICY_ACCOUNT_WILDCARD": Severity.LOW
    }


@pytest.mark.parametrize(
    "resource", ["bucket", "arn:aws:s3", "arn:nope:s3:::b", "arn:aws:sqs:us-east-1:12345:q", 7]
)
def test_malformed_arns(resource):
    assert ids(doc(allow("s3:GetObject", resource))) == {"POLICY_INVALID_ARN": Severity.HIGH}


@pytest.mark.parametrize("action", ["GetObject", "s3:Get Object", "s3:GetObject\n", 5, "s3:"])
def test_malformed_actions(action):
    assert ids(doc(allow(action))) == {"POLICY_INVALID_ACTION": Severity.HIGH}


@pytest.mark.parametrize(
    "document",
    [
        [],
        "policy",
        {"Version": "2012-10-17"},
        doc("not a statement"),
        doc({"Effect": "Maybe", "Action": "s3:GetObject", "Resource": "*"}),
        doc({"Effect": "Allow", "Resource": "*"}),
        doc({"Effect": "Allow", "Action": "s3:GetObject"}),
        doc(
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotAction": "s3:PutObject",
                "Resource": "*",
            }
        ),
        doc(allow("s3:GetObject", Sid="has space")),
        doc(allow("s3:GetObject", Condition=["x"])),
    ],
)
def test_structural_problems(document):
    assert ids(document).get("POLICY_INVALID_STRUCTURE") is Severity.HIGH


def test_version_and_duplicate_sid():
    assert ids(doc(allow("s3:GetObject"), version="2008-10-17")) == {
        "POLICY_VERSION": Severity.MEDIUM
    }
    duplicated = doc(allow("s3:GetObject", Sid="A"), allow("s3:PutObject", Sid="A"))
    assert ids(duplicated) == {"POLICY_DUPLICATE_SID": Severity.HIGH}


def test_single_statement_object_is_accepted():
    assert ids({"Version": "2012-10-17", "Statement": allow("s3:GetObject")}) == {}


def test_policy_variables_are_valid_resources():
    assert ids(doc(allow("s3:GetObject", "arn:aws:s3:::b/${aws:username}/*"))) == {}


def test_size_limit():
    big = doc(
        *[allow("s3:GetObject", f"arn:aws:s3:::bucket-{i}/*", Sid=f"S{i}") for i in range(120)]
    )
    assert ids(big) == {"POLICY_SIZE": Severity.MEDIUM}


def test_every_finding_is_actionable():
    for finding in validate_policy_document(doc(allow("*", "*"), allow("iam:PassRole", "*"))):
        assert finding.remediation and finding.why_it_matters and finding.documentation_url


def test_load_policy_file_reports_bad_json_and_huge_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert load_policy_file(bad)[1][0].id == "POLICY_INVALID_JSON"
    huge = tmp_path / "huge.json"
    huge.write_text(json.dumps({"Statement": ["x" * 1_100_000]}))
    assert load_policy_file(huge)[1][0].id == "POLICY_TOO_LARGE"
    nested = tmp_path / "nested.json"
    nested.write_text("[" * 200_000)
    assert load_policy_file(nested)[1][0].id == "POLICY_INVALID_JSON"


@pytest.mark.parametrize("action", ["*", "**", "*:*"])
@pytest.mark.parametrize("resource", ["*", "**", "arn:aws:*:*:*:*", "arn:*:*:*:*:*"])
def test_equivalent_spellings_of_full_admin_are_critical(action, resource):
    assert ids(doc(allow(action, resource))) == {"POLICY_FULL_ADMIN": Severity.CRITICAL}


@pytest.mark.parametrize("action", ["iam:passrole", "IAM:PassRole", "iam:Pass*", "iam:P?ssRole"])
@pytest.mark.parametrize(
    "resource", ["*", "arn:aws:iam::*:role/*", "arn:aws:iam::111122223333:role/*"]
)
def test_passrole_is_matched_case_insensitively_and_through_wildcards(action, resource):
    assert ids(doc(allow(action, resource)))["POLICY_PASSROLE_BROAD"] is Severity.HIGH


def test_passrole_restricted_to_a_service_is_not_flagged():
    statement = allow(
        "iam:PassRole",
        "*",
        Condition={"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}},
    )
    assert "POLICY_PASSROLE_BROAD" not in ids(doc(statement))


def test_action_checks_ignore_case():
    assert ids(doc(allow("S3:GETOBJECT", "*"))) == {"POLICY_RESOURCE_WILDCARD": Severity.MEDIUM}
    assert (
        ids(doc(allow("IAM:*", "arn:aws:iam::111122223333:role/x")))["POLICY_SERVICE_WILDCARD"]
        is Severity.HIGH
    )
    assert ids(doc(allow("s3:**")))["POLICY_SERVICE_WILDCARD"] is Severity.MEDIUM


def test_invalid_element_does_not_hide_breadth_of_the_rest():
    found = ids(doc(allow(["not an action", "*"], "*")))
    assert found == {
        "POLICY_INVALID_ACTION": Severity.HIGH,
        "POLICY_FULL_ADMIN": Severity.CRITICAL,
    }


def test_policy_variable_cannot_replace_the_arn():
    assert ids(doc(allow("s3:GetObject", "${aws:username}*"))) == {
        "POLICY_INVALID_ARN": Severity.HIGH
    }


def test_wildcard_service_in_resource_is_high():
    assert ids(doc(allow("s3:GetObject", "arn:aws:*:*::*"))) == {
        "POLICY_BROAD_RESOURCE": Severity.HIGH
    }


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "dup.json"
    path.write_text(
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Action": "s3:GetObject", "Action": "*", "Resource": "*"}]}'
    )
    document, findings = load_policy_file(path)
    assert document is None and findings[0].id == "POLICY_INVALID_JSON"
    assert "duplicate key 'Action'" in findings[0].problem


def test_a_condition_lowers_but_never_hides_privilege_escalation():
    statement = allow(
        "iam:AttachRolePolicy", "*", Condition={"Bool": {"aws:SecureTransport": "true"}}
    )
    assert ids(doc(statement))["POLICY_PRIVILEGE_ESCALATION"] is Severity.MEDIUM
    always_true = allow("iam:AttachRolePolicy", "*", Condition={"StringLike": {"aws:userid": "*"}})
    assert ids(doc(always_true))["POLICY_PRIVILEGE_ESCALATION"] is Severity.HIGH
