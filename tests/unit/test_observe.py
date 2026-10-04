import json
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from fmaws import observe as obs
from fmaws.aws.session import AWSClientProvider
from fmaws.cli.app import app
from fmaws.errors import AwsAuthError, ConfigError, FmawsError
from tests.conftest import REPO
from tests.unit.test_audit import ACCOUNT, FakeAWS, error

NOW = datetime.now(UTC)
ROLE = f"arn:aws:iam::{ACCOUNT}:role/app"
USER = f"arn:aws:iam::{ACCOUNT}:user/deployer"
runner = CliRunner()


def ago(days):
    return NOW - timedelta(days=days)


CUTOFF = ago(30)


def candidate(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(sid, actions, resource="*"):
    return {"Sid": sid, "Effect": "Allow", "Action": actions, "Resource": resource}


def service(prefix, last=None, **tracked):
    entry = {"ServiceName": prefix, "ServiceNamespace": prefix}
    if last is not None:
        entry["LastAuthenticated"] = last
    if tracked:
        entry["TrackedActionsLastAccessed"] = [
            {"ActionName": name, **({"LastAccessedTime": when} if when else {})}
            for name, when in tracked.items()
        ]
    return entry


def provider_for(responses):
    aws = FakeAWS(responses)
    provider = AWSClientProvider(region="us-east-1")
    provider.client = aws.client
    return provider, aws


def last_accessed_responses(*services, status="COMPLETED"):
    return {
        ("iam", "generate_service_last_accessed_details"): {"JobId": "job-1"},
        ("iam", "get_service_last_accessed_details"): {
            "JobStatus": status, "ServicesLastAccessed": list(services), "IsTruncated": False,
        },
    }  # fmt: skip


def evidence_from(*services):
    provider, _ = provider_for(last_accessed_responses(*services))
    evidence = obs.Evidence()
    obs.last_accessed(provider, ROLE, evidence)
    return evidence


def statuses(document, evidence):
    return {(o.action, o.status) for o in obs.classify(document, evidence, CUTOFF)}


# ------------------------------------------------------------------ classification


def test_each_status_from_last_accessed_information():
    evidence = evidence_from(
        service("s3", ago(1), GetObject=ago(2), PutObject=ago(200), DeleteObject=None,
                ListAllMyBuckets=ago(3)),
        service("sqs", ago(100)),
        service("sns", None),
        service("dynamodb", ago(1)),
    )  # fmt: skip
    document = candidate(
        allow("S3", ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]),
        allow("Queues", ["sqs:SendMessage"]),
        allow("Topics", "sns:Publish"),
        allow("Tables", ["dynamodb:GetItem"]),
        allow("Models", ["bedrock:InvokeModel"]),
    )
    assert statuses(document, evidence) == {
        ("s3:GetObject", obs.USED),
        ("s3:PutObject", obs.UNUSED),          # tracked, last used before the period
        ("s3:DeleteObject", obs.UNUSED),       # tracked, never used
        ("sqs:SendMessage", obs.UNUSED),       # whole service idle in the period
        ("sns:Publish", obs.UNUSED),           # whole service never used
        ("dynamodb:GetItem", obs.UNKNOWN),     # service used, action not tracked
        ("bedrock:InvokeModel", obs.UNKNOWN),  # no access today: cannot be observed
        ("s3:listallmybuckets", obs.MISSING),  # used, not in the candidate
    }  # fmt: skip


def test_unknown_is_never_reported_as_unused():
    observations = obs.classify(
        candidate(allow("T", "dynamodb:GetItem")),
        evidence_from(service("dynamodb", ago(1))),
        CUTOFF,
    )
    assert [o.status for o in observations] == [obs.UNKNOWN]
    assert "does not track this action" in observations[0].detail


def test_the_period_decides_between_used_and_unused():
    evidence = evidence_from(service("s3", ago(1), GetObject=ago(45)))
    document = candidate(allow("S3", "s3:GetObject"))
    assert {o.status for o in obs.classify(document, evidence, ago(30))} == {obs.UNUSED}
    assert {o.status for o in obs.classify(document, evidence, ago(60))} == {obs.USED}


def test_wildcard_actions_in_the_candidate_are_unknown():
    assert statuses(candidate(allow("S3", "s3:Get*")), evidence_from(service("s3", ago(1)))) == {
        ("s3:Get*", obs.UNKNOWN)
    }


def test_no_evidence_at_all_is_unknown():
    assert statuses(candidate(allow("S3", "s3:GetObject")), obs.Evidence()) == {
        ("s3:GetObject", obs.UNKNOWN)
    }


def test_action_matching_ignores_case_and_deny_statements_are_left_alone():
    evidence = evidence_from(service("s3", ago(1), GetObject=ago(1)))
    deny = {"Sid": "D", "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}
    document = candidate(allow("S3", "S3:getobject"), deny)
    assert statuses(document, evidence) == {("S3:getobject", obs.USED)}


# ------------------------------------------------------------------ last accessed mechanics


def test_last_accessed_polls_and_follows_pagination():
    pages = iter([
        {"JobStatus": "IN_PROGRESS"},
        {"JobStatus": "COMPLETED", "ServicesLastAccessed": [service("s3", ago(1))],
         "IsTruncated": True, "Marker": "m"},
        {"JobStatus": "COMPLETED", "ServicesLastAccessed": [service("sqs", ago(2))],
         "IsTruncated": False},
    ])  # fmt: skip
    provider, aws = provider_for({
        ("iam", "generate_service_last_accessed_details"): {"JobId": "job-1"},
        ("iam", "get_service_last_accessed_details"): lambda **_: next(pages),
    })  # fmt: skip
    evidence = obs.Evidence()
    waits = []
    obs.last_accessed(provider, ROLE, evidence, sleep=waits.append)
    assert set(evidence.services) == {"s3", "sqs"} and waits == [1]
    generate = next(c for c in aws.calls if c[1] == "generate_service_last_accessed_details")
    assert generate[3] == {"Arn": ROLE, "Granularity": "ACTION_LEVEL"}
    assert aws.calls[-1][3] == {"JobId": "job-1", "Marker": "m"}


def test_last_accessed_failure_and_timeout():
    provider, _ = provider_for(last_accessed_responses(status="FAILED"))
    with pytest.raises(FmawsError, match="could not produce"):
        obs.last_accessed(provider, ROLE, obs.Evidence())
    provider, _ = provider_for(last_accessed_responses(status="IN_PROGRESS"))
    with pytest.raises(FmawsError, match="in time"):
        obs.last_accessed(provider, ROLE, obs.Evidence(), sleep=lambda _: None)


def test_denied_and_unlisted_operations():
    provider, _ = provider_for(
        {("iam", "generate_service_last_accessed_details"): error("AccessDenied")}
    )
    with pytest.raises(AwsAuthError, match="iam:GenerateServiceLastAccessedDetails"):
        obs.last_accessed(provider, ROLE, obs.Evidence())
    with pytest.raises(RuntimeError, match="not an allow-listed"):
        obs._call(provider, "iam", "delete_role", RoleName="app")


def test_permission_manifest_matches_the_allow_list():
    manifest = json.loads((REPO / "permissions" / "observe-policy.json").read_text())
    assert manifest == obs.permission_manifest()
    for (_, operation), permission in obs.OPERATIONS.items():
        assert operation.startswith(("get_", "lookup_", "generate_service_last_accessed"))
        assert permission.split(":")[1].startswith(("Get", "Lookup", "Generate"))
    assert "access-analyzer:StartPolicyGeneration" not in manifest["Statement"][0]["Action"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(ROLE, ROLE), ("role/app", ROLE), ("user/deployer", USER), (USER, USER)],
)
def test_principal_forms(value, expected):
    assert obs.principal_arn(value, ACCOUNT) == expected


@pytest.mark.parametrize(
    "value",
    [
        "app",
        f"arn:aws:iam::{ACCOUNT}:group/devs",
        "arn:aws:s3:::bucket",
        f"arn:aws:iam::{ACCOUNT}:root",
    ],
)
def test_invalid_principals(value):
    with pytest.raises(ConfigError):
        obs.principal_arn(value, ACCOUNT)


# ------------------------------------------------------------------ CloudTrail


def event(name, source="sqs.amazonaws.com", arn=ROLE, days=1, code=None, user=False):
    identity = (
        {"type": "IAMUser", "arn": arn}
        if user
        else {"type": "AssumedRole", "arn": arn.replace(":iam:", ":sts:").replace("role/", "assumed-role/") + "/s",
              "sessionContext": {"sessionIssuer": {"arn": arn}}}
    )  # fmt: skip
    detail = {"eventSource": source, "eventName": name, "userIdentity": identity}
    if code:
        detail["errorCode"] = code
    return {"EventTime": ago(days), "CloudTrailEvent": json.dumps(detail)}


def trail(*pages):
    remaining = iter(pages)
    return {("cloudtrail", "lookup_events"): lambda **_: next(remaining)}


def lookup(responses, arn=ROLE, max_events=2000):
    provider, aws = provider_for(responses)
    evidence = obs.Evidence()
    waits = []
    obs.cloudtrail_events(provider, arn, evidence, ago(30), NOW, "us-east-1", max_events,
                          sleep=waits.append)  # fmt: skip
    return evidence, aws, waits


def test_cloudtrail_events_are_filtered_to_the_principal():
    other = f"arn:aws:iam::{ACCOUNT}:role/other"
    evidence, aws, _ = lookup(trail({"Events": [
        event("SendMessage"),
        event("SendMessage", days=5),
        event("DeleteQueue", arn=other),
        event("PutMetricData", source="monitoring.amazonaws.com"),
        event("CreateTopic", source="sns.amazonaws.com", code="AccessDenied"),
        {"EventTime": ago(1), "CloudTrailEvent": "{broken"},
    ]}))  # fmt: skip
    assert set(evidence.events) == {"sqs:SendMessage", "cloudwatch:PutMetricData"}
    assert evidence.events["sqs:SendMessage"] == ago(1)
    assert set(evidence.denied) == {"sns:CreateTopic"}
    assert "LookupAttributes" not in aws.calls[0][3]  # roles cannot be filtered server-side
    assert any("Data events" in note for note in evidence.notes)


def test_cloudtrail_user_lookup_is_filtered_server_side():
    _, aws, _ = lookup(trail({"Events": [event("SendMessage", arn=USER, user=True)]}), arn=USER)
    assert aws.calls[0][3]["LookupAttributes"] == [
        {"AttributeKey": "Username", "AttributeValue": "deployer"}
    ]


def test_cloudtrail_lookup_is_paced_and_capped():
    page = {"Events": [event("SendMessage")] * 50, "NextToken": "more"}
    evidence, aws, waits = lookup(trail(page, page, page, {"Events": []}), max_events=100)
    assert len(aws.calls) == 2 and waits == [obs.LOOKUP_PAUSE]
    assert aws.calls[1][3]["NextToken"] == "more"
    assert any("stopped after 100 events" in note for note in evidence.notes)


def test_cloudtrail_upgrades_and_reports_missing_and_denied():
    evidence = evidence_from(service("sqs", ago(1)))
    provider, _ = provider_for(trail({"Events": [
        event("SendMessage"),
        event("PurgeQueue"),
        event("Publish", source="sns.amazonaws.com", code="AccessDenied"),
    ]}))  # fmt: skip
    obs.cloudtrail_events(provider, ROLE, evidence, ago(30), NOW, None, 2000)
    result = {
        o.action: o
        for o in obs.classify(candidate(allow("Q", "sqs:SendMessage")), evidence, CUTOFF)
    }
    assert (
        result["sqs:SendMessage"].status == obs.USED
        and result["sqs:SendMessage"].source == "CloudTrail"
    )
    assert result["sqs:PurgeQueue"].status == obs.MISSING
    assert result["sns:Publish"].status == obs.MISSING and "denied" in result["sns:Publish"].detail


# ------------------------------------------------------------------ observed policy


def test_observed_policy_marks_used_and_missing():
    evidence = evidence_from(service("s3", ago(1)))
    observed = candidate(allow("O", ["s3:GetObject", "s3:ListBucket", "kms:Decrypt"]))
    obs.observed_policy(observed, evidence, "observed policy x.json")
    document = candidate(allow("S3", ["s3:GetObject", "s3:PutObject"]))
    assert statuses(document, evidence) == {
        ("s3:GetObject", obs.USED),
        ("s3:PutObject", obs.UNKNOWN),
        ("s3:ListBucket", obs.MISSING),
        ("kms:Decrypt", obs.MISSING),
    }
    with pytest.raises(ConfigError, match="no Allow actions"):
        obs.observed_policy({"Statement": []}, obs.Evidence(), "empty")


def test_access_analyzer_job_is_read_never_started():
    generated = {"policy": json.dumps(candidate(allow("G", "sqs:SendMessage")))}
    provider, aws = provider_for({("accessanalyzer", "get_generated_policy"): {
        "jobDetails": {"status": "SUCCEEDED"},
        "generatedPolicyResult": {"generatedPolicies": [generated]},
    }})  # fmt: skip
    evidence = obs.Evidence()
    obs.access_analyzer_job(provider, "job-9", evidence)
    assert evidence.observed == ["sqs:SendMessage"]
    assert [c[1] for c in aws.calls] == ["get_generated_policy"]
    provider, _ = provider_for({("accessanalyzer", "get_generated_policy"): {
        "jobDetails": {"status": "IN_PROGRESS"}}})  # fmt: skip
    with pytest.raises(FmawsError, match="is IN_PROGRESS"):
        obs.access_analyzer_job(provider, "job-9", obs.Evidence())


# ------------------------------------------------------------------ recommended policy


def recommended(days, declared=frozenset()):
    evidence = evidence_from(
        service("s3", ago(1), GetObject=ago(1), PutObject=None), service("dynamodb", ago(1))
    )
    document = candidate(
        allow("S3", ["s3:GetObject", "s3:PutObject"]),
        allow("Tables", "dynamodb:GetItem"),
        allow("OnlyUnused", "s3:PutObject"),
    )
    observations = obs.classify(document, evidence, ago(days))
    return obs.recommend(document, observations, days, 90, set(declared)), observations


def test_short_periods_never_remove_anything():
    policy, observations = recommended(30)
    assert [s["Sid"] for s in policy["Statement"]] == ["S3", "Tables", "OnlyUnused"]
    assert policy["Statement"][0]["Action"] == ["s3:GetObject", "s3:PutObject"]
    assert not any(o.removed for o in observations)


def test_long_periods_remove_only_unused_and_say_so():
    policy, observations = recommended(120)
    assert policy["Statement"] == [
        {"Sid": "S3", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Sid": "Tables", "Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"},
    ]
    assert {(o.statement, o.action) for o in observations if o.removed} == {
        ("S3", "s3:PutObject"),
        ("OnlyUnused", "s3:PutObject"),
    }
    unknown = next(o for o in observations if o.action == "dynamodb:GetItem")
    assert unknown.status == obs.UNKNOWN and not unknown.removed


def test_declared_permissions_are_never_removed():
    policy, observations = recommended(120, declared={"S3", "OnlyUnused"})
    assert [s["Sid"] for s in policy["Statement"]] == ["S3", "Tables", "OnlyUnused"]
    assert not any(o.removed for o in observations)


# ------------------------------------------------------------------ CLI


@pytest.fixture
def cli(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def invoke(responses, *args, config=None):
        aws = FakeAWS(responses)
        monkeypatch.setattr(AWSClientProvider, "client", lambda self, s, r=None: aws.client(s, r))
        monkeypatch.setattr(
            AWSClientProvider, "identity",
            lambda self: {"account": ACCOUNT, "arn": USER},
        )  # fmt: skip
        monkeypatch.setattr(obs.time, "sleep", lambda _: None)
        if config is not None:
            (tmp_path / "fmaws.yaml").write_text(json.dumps(config))
        result = runner.invoke(app, ["observe", *args])
        return result, aws, tmp_path

    return invoke


SQS_PROJECT = {
    "aws": {"region": "us-east-1", "account_id": ACCOUNT},
    "resources": {"sqs": [{"queue": "orders", "actions": ["send", "receive"]}]},
}
SQS_EVIDENCE = last_accessed_responses(
    service("sqs", ago(1), SendMessage=ago(1), ReceiveMessage=None, DeleteMessage=None,
            ChangeMessageVisibility=None)
)  # fmt: skip


def test_cli_observe_generated_policy(cli):
    result, _, _ = cli(SQS_EVIDENCE, "--principal", "role/app", config=SQS_PROJECT)
    assert result.exit_code == 0, result.output
    assert f"Principal: {ROLE}" in result.output
    assert "Observation period: 30 days" in result.output
    assert "Sources: IAM last accessed" in result.output
    assert "Used permission: 1" in result.output and "Unused permission: 3" in result.output
    assert "Unknown permission: 0" in result.output
    assert "Potentially missing permission: 0" in result.output
    assert "not the same as unnecessary" in result.output
    assert "No permission was removed" in result.output


def test_cli_declared_permissions_survive_a_long_period(cli):
    result, _, root = cli(SQS_EVIDENCE, "--principal", ROLE, "--days", "120", "--output", "rec.json",
                          config=SQS_PROJECT)  # fmt: skip
    assert result.exit_code == 0, result.output
    actions = json.loads((root / "rec.json").read_text())["Statement"][0]["Action"]
    assert "sqs:ReceiveMessage" in actions
    assert "never removed by observation" in result.output


def test_cli_policy_file_long_period_writes_recommended_policy(cli, tmp_path):
    (tmp_path / "current.json").write_text(json.dumps(candidate(
        allow("Q", ["sqs:SendMessage", "sqs:ReceiveMessage"]))))  # fmt: skip
    result, _, root = cli(SQS_EVIDENCE, "--principal", ROLE, "--policy", "current.json",
                          "--days", "120", "--output", "rec.json", "--format", "json")  # fmt: skip
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"] == {"potentially_missing": 0, "unused": 1, "unknown": 0, "used": 1}
    assert [o["action"] for o in data["observations"] if o["removed"]] == ["sqs:ReceiveMessage"]
    assert (
        json.loads((root / "rec.json").read_text())["Statement"][0]["Action"] == "sqs:SendMessage"
    )
    assert "not the same as unnecessary" in data["notice"]


def test_cli_cloudtrail_and_markdown(cli, tmp_path):
    (tmp_path / "current.json").write_text(json.dumps(candidate(allow("Q", "sqs:SendMessage"))))
    responses = {**SQS_EVIDENCE, **trail({"Events": [event("PurgeQueue")]})}
    result, aws, _ = cli(responses, "--principal", ROLE, "--policy", "current.json",
                         "--cloudtrail", "--region", "us-east-1", "--format", "markdown")  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "| POTENTIALLY MISSING | `sqs:PurgeQueue` |" in result.output
    assert "CloudTrail management events (us-east-1)" in result.output
    assert any(c[1] == "lookup_events" for c in aws.calls)


def test_cli_errors(cli, tmp_path):
    missing_principal, _, _ = cli(SQS_EVIDENCE, config=SQS_PROJECT)
    assert missing_principal.exit_code == 2 and "--principal" in missing_principal.output
    nothing, _, _ = cli(SQS_EVIDENCE, "--principal", ROLE, config={})
    assert nothing.exit_code == 2 and "no candidate policy" in nothing.output
    (tmp_path / "bad.json").write_text("{nope")
    bad, _, _ = cli(SQS_EVIDENCE, "--principal", ROLE, "--policy", "bad.json")
    assert bad.exit_code == 2
    denied, _, _ = cli(
        {("iam", "generate_service_last_accessed_details"): error("AccessDenied")},
        "--principal", ROLE, config=SQS_PROJECT,
    )  # fmt: skip
    assert denied.exit_code == 3 and "iam:GenerateServiceLastAccessedDetails" in denied.output


def test_not_action_statements_are_reported_and_never_dropped():
    not_action = {"Sid": "Rest", "Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    document = candidate(allow("S3", "s3:PutObject"), not_action)
    evidence = evidence_from(service("s3", ago(1), PutObject=None))
    for days in (30, 120):
        observations = obs.classify(document, evidence, ago(days))
        assert ("NotAction", obs.UNKNOWN, "Rest") in {
            (o.action, o.status, o.statement) for o in observations
        }
        policy = obs.recommend(document, observations, days, 90, set())
        assert not_action in policy["Statement"]


def test_cli_merged_declared_and_discovered_statement_is_never_trimmed(cli, tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_sqs_queue" "extra" {\n  name = "extra"\n}\n')
    project = {**SQS_PROJECT, "resources": {"sqs": [{"queue": "orders", "actions": ["read"]}]}}
    evidence = last_accessed_responses(
        service("sqs", ago(1), GetQueueAttributes=None, GetQueueUrl=None)
    )
    result, _, root = cli(evidence, "--principal", ROLE, "--days", "120", "--output", "rec.json",
                          config=project)  # fmt: skip
    assert result.exit_code == 0, result.output
    statement = json.loads((root / "rec.json").read_text())["Statement"][0]
    assert len(statement["Resource"]) == 2  # declared and discovered queue share one statement
    assert statement["Action"] == ["sqs:GetQueueAttributes", "sqs:GetQueueUrl"]
