import json

import pytest

from fmaws.errors import ConfigError
from fmaws.models.policy import Explanation, Statement
from fmaws.models.requirement import Confidence, ResourceRequirement, SourceRef
from fmaws.policy import catalog
from fmaws.policy.arns import ArnContext, iam_match, parse_arn
from fmaws.policy.generator import generate_policy
from fmaws.policy.optimizer import optimize

CTX = ArnContext(region="us-east-1", account="111122223333")
EXPLAIN = (Explanation(reason="r", source="fmaws.yaml:1", confidence=Confidence.HIGH),)


def req(service, resource, intents, confidence=Confidence.HIGH, **options):
    return ResourceRequirement(
        service=service,
        resource=resource,
        intents=intents,
        confidence=confidence,
        source=SourceRef(file="fmaws.yaml", line=3),
        reason="Declared in configuration",
        options=options,
    )


def statements(*reqs, ctx=CTX):
    return generate_policy(list(reqs), ctx).to_iam()["Statement"]


def stmt(actions, resources, conditions=None):
    return Statement(
        actions=tuple(actions), resources=tuple(resources), conditions=conditions or {},
        explanations=EXPLAIN,
    )  # fmt: skip


def test_dynamodb_read_includes_indexes_but_not_writes():
    (statement,) = statements(req("dynamodb", "customers", ("read",)))
    assert statement["Action"] == [
        "dynamodb:BatchGetItem",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
    ]
    assert statement["Resource"] == [
        "arn:aws:dynamodb:us-east-1:111122223333:table/customers",
        "arn:aws:dynamodb:us-east-1:111122223333:table/customers/index/*",
    ]


def test_secret_arn_uses_six_character_suffix():
    (statement,) = statements(req("secretsmanager", "prod/ecommerce/api", ("read",)))
    assert statement["Action"] == "secretsmanager:GetSecretValue"
    assert statement["Resource"] == (
        "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/ecommerce/api-??????"
    )


def test_full_arn_is_used_verbatim():
    arn = "arn:aws:sqs:eu-west-1:444455556666:order-processing"
    (statement,) = statements(req("sqs", arn, ("send",)))
    assert statement["Resource"] == arn


def test_malformed_arn_rejected():
    with pytest.raises(ConfigError, match="Malformed"):
        statements(req("sqs", "arn:aws:sqs:order-processing", ("send",)))


@pytest.mark.parametrize("name", ["*", "orders*", "a b", 'x"y', "tab\tname"])
def test_wildcards_and_injection_in_names_rejected(name):
    with pytest.raises(ConfigError):
        statements(req("dynamodb", name, ("read",)))


def test_star_actions_get_their_own_explained_statement():
    policy = generate_policy([req("dynamodb", "customers", ("read", "list"))], CTX)
    star = [s for s in policy.statements if s.resources == ("*",)]
    assert [s.actions for s in star] == [("dynamodb:ListTables",)]
    assert "does not support resource-level permissions" in star[0].explanations[0].reason
    assert all("*" not in s.resources for s in policy.statements if s is not star[0])


def test_kms_alias_is_scoped_with_condition():
    (statement,) = statements(req("kms", "alias/app", ("decrypt",)))
    assert statement["Resource"] == "arn:aws:kms:us-east-1:111122223333:key/*"
    assert statement["Condition"] == {
        "ForAnyValue:StringEquals": {"kms:ResourceAliases": ["alias/app"]}
    }


def test_bedrock_foundation_model_and_inference_profile():
    (model,) = statements(req("bedrock", "anthropic.claude-3-haiku-20240307-v1:0", ("invoke",)))
    assert model["Resource"] == (
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
    )
    (profile,) = statements(
        req("bedrock", "us.anthropic.claude-3-haiku-20240307-v1:0", ("invoke",))
    )
    assert profile["Resource"] == [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
        "arn:aws:bedrock:us-east-1:111122223333:inference-profile/"
        "us.anthropic.claude-3-haiku-20240307-v1:0",
    ]


def test_companion_kms_statement_for_encrypted_queue():
    result = statements(req("sqs", "orders", ("receive",), kms_key="abcd-1234"))
    kms = [s for s in result if s["Action"] == "kms:Decrypt"][0]
    assert kms["Resource"] == "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
    assert kms["Condition"] == {"StringEquals": {"kms:ViaService": ["sqs.us-east-1.amazonaws.com"]}}


def test_unknown_service_and_intent():
    with pytest.raises(ConfigError, match="Unsupported service"):
        statements(req("glacier", "x", ("read",)))
    with pytest.raises(ConfigError, match="Unknown action 'publish' for sqs"):
        statements(req("sqs", "x", ("publish",)))


def test_generation_is_deterministic_and_order_independent():
    reqs = [
        req("sqs", "orders", ("send", "receive")),
        req("dynamodb", "customers", ("read",)),
        req("s3", "assets-bucket", ("read", "list"), prefixes=["b/", "a/"]),
        req("sns", "order-events", ("publish",)),
    ]
    first = generate_policy(reqs, CTX).to_json()
    assert first == generate_policy(list(reversed(reqs)), CTX).to_json()
    sids = [s["Sid"] for s in json.loads(first)["Statement"]]
    assert len(set(sids)) == len(sids)
    assert all(sid.isalnum() for sid in sids)


def test_every_statement_is_explained():
    policy = generate_policy(
        [req("sqs", "orders", ("send",)), req("s3", "assets-bucket", ("read",), kms_key="k1")], CTX
    )
    for statement in policy.statements:
        assert statement.explanations
        assert all(e.source == "fmaws.yaml:3" for e in statement.explanations)


def test_no_generated_action_contains_a_wildcard():
    for definition in catalog.CATALOG.values():
        for actions in [*definition.intents.values(), *definition.kms_actions.values()]:
            assert all("*" not in a and a.count(":") == 1 for a in actions)


def test_parse_arn_round_trip():
    definition = catalog.get("secretsmanager")
    parsed = parse_arn(definition, "arn:aws:secretsmanager:us-east-1:111122223333:secret:db-AbCdEf")
    assert parsed and parsed["name"] == "db" and parsed["account"] == "111122223333"
    assert parse_arn(definition, "arn:aws:sqs:us-east-1:111122223333:q") is None
    logs = parse_arn(catalog.get("logs"), "arn:aws:logs:us-east-1:111122223333:log-group:/app/x")
    assert logs and logs["name"] == "/app/x"


def test_iam_match():
    assert iam_match("arn:aws:s3:::b/*", "arn:aws:s3:::b/uploads/*")
    assert iam_match("*", "anything")
    assert iam_match("secret:x-??????", "secret:x-AbCdEf")
    assert not iam_match("arn:aws:s3:::b/uploads/*", "arn:aws:s3:::b/*")


def test_optimizer_merges_actions_for_identical_resources():
    (merged,) = optimize(
        [stmt(["s3:GetObject"], ["r/a"]), stmt(["s3:PutObject", "s3:GetObject"], ["r/a"])]
    )
    assert merged.actions == ("s3:GetObject", "s3:PutObject")


def test_optimizer_merges_resources_for_identical_actions():
    (merged,) = optimize([stmt(["s3:GetObject"], ["r/b"]), stmt(["s3:GetObject"], ["r/a"])])
    assert merged.resources == ("r/a", "r/b")


def test_optimizer_keeps_different_conditions_apart():
    one = stmt(["s3:ListBucket"], ["b"], {"StringLike": {"s3:prefix": ["a/*"]}})
    two = stmt(["s3:ListBucket"], ["b"], {"StringLike": {"s3:prefix": ["b/*"]}})
    assert len(optimize([one, two])) == 2


def test_optimizer_never_merges_across_services():
    result = optimize([stmt(["sqs:ListQueues"], ["*"]), stmt(["sns:ListTopics"], ["*"])])
    assert len(result) == 2


def test_optimizer_removes_subsumed_resources_and_redundant_statements():
    (only,) = optimize(
        [stmt(["s3:GetObject"], ["b/*", "b/uploads/*"]), stmt(["s3:GetObject"], ["b/reports/*"])]
    )
    assert only.resources == ("b/*",)


def test_optimizer_does_not_drop_action_covered_only_under_a_condition():
    conditional = stmt(["s3:GetObject"], ["b/*"], {"Bool": {"aws:SecureTransport": ["true"]}})
    plain = stmt(["s3:GetObject", "s3:PutObject"], ["b/x/*"])
    result = optimize([conditional, plain])
    assert any(s.actions == ("s3:GetObject", "s3:PutObject") for s in result)


def test_optimizer_keeps_explanations_of_dropped_statements():
    narrow = stmt(["s3:GetObject"], ["b/x/*"]).model_copy(
        update={
            "explanations": (
                Explanation(reason="narrow", source="a.tf:1", confidence=Confidence.LOW),
            )
        }
    )
    (only,) = optimize([stmt(["s3:GetObject", "s3:PutObject"], ["b/*"]), narrow])
    assert {e.reason for e in only.explanations} == {"r", "narrow"}
    assert only.confidence is Confidence.LOW


@pytest.mark.parametrize("name", ["customers\n", "\ncustomers", "customers\n*"])
def test_names_with_newlines_are_rejected(name):
    with pytest.raises(ConfigError):
        statements(req("dynamodb", name, ("read",)))
    assert parse_arn(catalog.get("sqs"), "arn:aws:sqs:us-east-1:111122223333:q\n") is None


@pytest.mark.parametrize(
    "fields",
    [
        {"region": "us-east-1:999999999999"},
        {"region": "us-east-1/*"},
        {"region": "US-EAST-1"},
        {"partition": "aws:x"},
        {"account": "12345"},
        {"account": "111122223333:table/other"},
    ],
)
def test_arn_context_rejects_values_that_would_shift_or_widen_arn_fields(fields):
    with pytest.raises(ConfigError):
        ArnContext(**fields)


def test_arn_context_accepts_real_regions_and_wildcards():
    for region in ("us-east-1", "ap-southeast-2", "us-gov-west-1", "cn-north-1", "*"):
        assert ArnContext(region=region, account="*").region == region


def test_iam_match_without_wildcards_is_plain_equality():
    assert iam_match("arn:aws:s3:::b/a.b", "arn:aws:s3:::b/a.b")
    assert not iam_match("arn:aws:s3:::b/a.b", "arn:aws:s3:::b/aXb")
