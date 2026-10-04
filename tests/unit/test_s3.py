import pytest

from fmaws.errors import ConfigError
from fmaws.models.requirement import Confidence, ResourceRequirement, SourceRef
from fmaws.policy.arns import ArnContext
from fmaws.policy.generator import generate_policy
from fmaws.policy.s3 import normalize_prefix

CTX = ArnContext(region="ap-south-1", account="111122223333")


def s3req(bucket="example-bucket", intents=("read",), **options):
    return ResourceRequirement(
        service="s3",
        resource=bucket,
        intents=intents,
        confidence=Confidence.HIGH,
        source=SourceRef(file="fmaws.yaml", line=1),
        reason="Declared in configuration",
        options=options,
    )


def policy(*reqs, ctx=CTX, include_conditions=True):
    return generate_policy(list(reqs), ctx, include_conditions).to_iam()["Statement"]


def by_action(statements, action):
    return [
        s
        for s in statements
        if action in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", ""),
        ("/", ""),
        ("*", ""),
        ("uploads", "uploads/"),
        ("uploads/", "uploads/"),
        ("/uploads/", "uploads/"),
        ("a/b/c", "a/b/c/"),
        ("uploads/img-*", "uploads/img-"),
        ("uploads/*", "uploads/"),
    ],
)
def test_normalize_prefix(raw, expected):
    assert normalize_prefix(raw) == expected


@pytest.mark.parametrize("bad", ["up*loads/", "a?b/", "has space/", 'q"uote/'])
def test_prefix_wildcards_and_junk_rejected(bad):
    with pytest.raises(ConfigError):
        normalize_prefix(bad)


def test_folder_access_matches_documented_pattern():
    statements = policy(s3req(intents=("read", "write", "list"), prefixes=["uploads/"]))
    assert len(statements) == 2
    listing = by_action(statements, "s3:ListBucket")[0]
    assert listing["Resource"] == "arn:aws:s3:::example-bucket"
    assert listing["Condition"] == {"StringLike": {"s3:prefix": ["uploads/*"]}}
    objects = by_action(statements, "s3:GetObject")[0]
    assert objects["Action"] == ["s3:GetObject", "s3:PutObject"]
    assert objects["Resource"] == "arn:aws:s3:::example-bucket/uploads/*"


def test_folder_permission_is_never_widened_to_bucket():
    statements = policy(s3req(intents=("read", "write", "delete", "list"), prefixes=["a/", "b/c"]))
    for statement in statements:
        resources = statement["Resource"]
        for resource in [resources] if isinstance(resources, str) else resources:
            assert resource != "arn:aws:s3:::example-bucket/*"
            assert resource != "*"
        if statement["Resource"] == "arn:aws:s3:::example-bucket":
            assert statement["Condition"]["StringLike"]["s3:prefix"] == ["a/*", "b/c/*"]


def test_root_access_has_no_prefix_condition():
    statements = policy(s3req(intents=("read", "list")))
    listing = by_action(statements, "s3:ListBucket")[0]
    assert "Condition" not in listing
    assert by_action(statements, "s3:GetObject")[0]["Resource"] == "arn:aws:s3:::example-bucket/*"


def test_bucket_only_and_object_only():
    assert [s["Action"] for s in policy(s3req(intents=("list",), prefixes=["x/"]))] == [
        "s3:ListBucket"
    ]
    only_objects = policy(s3req(intents=("read",), prefixes=["x/"]))
    assert [s["Action"] for s in only_objects] == ["s3:GetObject"]


def test_duplicate_and_equivalent_prefixes_collapse():
    statements = policy(s3req(prefixes=["uploads", "uploads/", "/uploads/"]))
    assert len(statements) == 1
    assert statements[0]["Resource"] == "arn:aws:s3:::example-bucket/uploads/*"


def test_nested_prefix_covered_by_parent_is_dropped():
    statements = policy(s3req(intents=("read",), prefixes=["uploads/", "uploads/2024/"]))
    assert [s["Resource"] for s in statements] == ["arn:aws:s3:::example-bucket/uploads/*"]


def test_nested_prefix_keeps_only_additional_actions():
    statements = policy(
        s3req(intents=("read",), prefixes=["uploads/"]),
        s3req(intents=("read", "write"), prefixes=["uploads/tmp/"]),
    )
    assert {(s["Action"], s["Resource"]) for s in statements} == {
        ("s3:GetObject", "arn:aws:s3:::example-bucket/uploads/*"),
        ("s3:PutObject", "arn:aws:s3:::example-bucket/uploads/tmp/*"),
    }


def test_sibling_prefixes_with_same_actions_merge_resources_not_scope():
    statements = policy(s3req(intents=("read",), prefixes=["a/", "b/"]))
    assert statements[0]["Resource"] == [
        "arn:aws:s3:::example-bucket/a/*",
        "arn:aws:s3:::example-bucket/b/*",
    ]


def test_multipart_and_versioning():
    statements = policy(
        s3req(intents=("read", "write", "delete", "list"), prefixes=["v/"], multipart=True,
              versioned=True)
    )  # fmt: skip
    assert by_action(statements, "s3:GetObject")[0]["Action"] == [
        "s3:AbortMultipartUpload",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListMultipartUploadParts",
        "s3:PutObject",
    ]
    assert by_action(statements, "s3:ListBucket")[0]["Action"] == [
        "s3:ListBucket",
        "s3:ListBucketVersions",
    ]


def test_multipart_without_write_adds_nothing():
    statements = policy(s3req(intents=("read",), multipart=True))
    assert statements[0]["Action"] == "s3:GetObject"


def test_bucket_location_is_opt_in():
    assert not by_action(policy(s3req()), "s3:GetBucketLocation")
    located = by_action(policy(s3req(bucket_location=True)), "s3:GetBucketLocation")[0]
    assert located["Resource"] == "arn:aws:s3:::example-bucket"


def test_kms_permissions_follow_intents():
    key = "1234abcd-12ab-34cd-56ef-1234567890ab"
    read = by_action(policy(s3req(intents=("read",), kms_key=key)), "kms:Decrypt")[0]
    assert read["Action"] == "kms:Decrypt"
    assert read["Resource"] == f"arn:aws:kms:ap-south-1:111122223333:key/{key}"
    assert read["Condition"] == {
        "StringEquals": {"kms:ViaService": ["s3.ap-south-1.amazonaws.com"]}
    }
    write = policy(s3req(intents=("write",), kms_key=key))
    assert by_action(write, "kms:GenerateDataKey")[0]["Action"] == "kms:GenerateDataKey"
    multipart = policy(s3req(intents=("write",), kms_key=key, multipart=True))
    assert by_action(multipart, "kms:Decrypt")[0]["Action"] == [
        "kms:Decrypt",
        "kms:GenerateDataKey",
    ]


def test_include_conditions_false_omits_optional_conditions_but_keeps_prefix():
    statements = policy(
        s3req(intents=("read", "list"), prefixes=["p/"], kms_key="abc", account_id="999988887777"),
        include_conditions=False,
    )
    assert "Condition" not in by_action(statements, "kms:Decrypt")[0]
    assert by_action(statements, "s3:ListBucket")[0]["Condition"] == {
        "StringLike": {"s3:prefix": ["p/*"]}
    }


def test_cross_account_bucket_is_pinned_to_owner():
    statements = policy(s3req(intents=("read",), account_id="999988887777"))
    assert statements[0]["Condition"] == {"StringEquals": {"s3:ResourceAccount": ["999988887777"]}}


def test_multiple_buckets_stay_separate():
    statements = policy(
        s3req("assets-bucket", ("read", "list"), prefixes=["img/"]),
        s3req("reports-bucket", ("read", "list"), prefixes=["reports/"]),
    )
    listings = by_action(statements, "s3:ListBucket")
    assert {(s["Resource"], s["Condition"]["StringLike"]["s3:prefix"][0]) for s in listings} == {
        ("arn:aws:s3:::assets-bucket", "img/*"),
        ("arn:aws:s3:::reports-bucket", "reports/*"),
    }


@pytest.mark.parametrize("bucket", ["*", "Bucket", "a", "my-bucket/*", "x" * 64, "a b"])
def test_invalid_bucket_names_rejected(bucket):
    with pytest.raises(ConfigError):
        policy(s3req(bucket))


def test_unknown_action_rejected():
    with pytest.raises(ConfigError, match="Unknown action 'admin'"):
        policy(s3req(intents=("admin",)))


def test_no_wildcard_actions_ever():
    statements = policy(
        s3req(intents=("read", "write", "delete", "list"), multipart=True, versioned=True,
              bucket_location=True, kms_key="abc")
    )  # fmt: skip
    for statement in statements:
        actions = statement["Action"]
        for action in [actions] if isinstance(actions, str) else actions:
            assert "*" not in action


@pytest.mark.parametrize("bucket", ["my-bucket\n", " my-bucket", "my-bucket\n/*"])
def test_bucket_names_with_whitespace_are_rejected(bucket):
    with pytest.raises(ConfigError):
        policy(s3req(bucket))


@pytest.mark.parametrize("prefix", ["uploads/\n", "uploads/\n*", " uploads/"])
def test_prefixes_with_whitespace_are_rejected(prefix):
    with pytest.raises(ConfigError):
        policy(s3req(prefixes=[prefix]))
