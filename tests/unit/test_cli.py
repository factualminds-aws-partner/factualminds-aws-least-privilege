import json
import shutil

import boto3
import pytest
from botocore.stub import Stubber
from typer.testing import CliRunner

from fmaws.aws.session import AWSClientProvider
from fmaws.cli.app import app
from tests.conftest import REPO

runner = CliRunner()
EXAMPLE = REPO / "examples" / "ecommerce-ai-agent"
FIXTURES = REPO / "tests" / "fixtures"
ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
CLEAN = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-one/a/*"}
    ],
}


@pytest.fixture
def project(tmp_path, monkeypatch):
    def use(source=None):
        target = tmp_path / "project"
        if source:
            shutil.copytree(source, target)
        else:
            target.mkdir()
        monkeypatch.chdir(target)
        return target

    return use


@pytest.fixture
def stubbed(monkeypatch):
    """Stubbed STS and Access Analyzer clients behind the provider. No network."""
    clients = {
        "sts": boto3.client("sts", region_name="us-east-1"),
        "accessanalyzer": boto3.client("accessanalyzer", region_name="us-east-1"),
    }
    stubs = {name: Stubber(client) for name, client in clients.items()}
    monkeypatch.setattr(
        AWSClientProvider, "client", lambda self, service, region=None: clients[service]
    )
    for stub in stubs.values():
        stub.activate()
    return stubs


def test_version_and_help():
    assert runner.invoke(app, ["--version"]).output.startswith("fmaws ")
    output = runner.invoke(app, ["--help"]).output
    for command in ("generate", "explain", "validate", "doctor", "audit", "observe"):
        assert command in output


def test_generate_writes_valid_policy_and_reports(project):
    root = project(EXAMPLE)
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 0, result.output
    assert "Generated policy: generated-policy.json" in result.output
    assert "Local validation: PASS" in result.output
    assert "AWS IAM Access Analyzer: NOT RUN" in result.output
    assert "0 errors" in result.output
    assert "ecommerce-agent-traces" in result.output  # unconfirmed discovered bucket
    policy = json.loads((root / "generated-policy.json").read_text())
    assert policy == json.loads((REPO / "tests/golden/ecommerce-ai-agent.json").read_text())


def test_generate_twice_is_identical_and_ignores_its_own_output(project):
    root = project(EXAMPLE)
    runner.invoke(app, ["generate"])
    first = (root / "generated-policy.json").read_text()
    runner.invoke(app, ["generate"])
    assert (root / "generated-policy.json").read_text() == first


def test_generate_explain_shows_reason_source_confidence(project):
    project(EXAMPLE)
    output = runner.invoke(app, ["generate", "--explain"]).output
    assert "Reason:" in output and "Source: fmaws.yaml:" in output and "Confidence: HIGH" in output
    assert "s3://ecommerce-assets/product-images/*" in output


def test_generate_json_and_markdown_formats(project):
    project(EXAMPLE)
    data = json.loads(runner.invoke(app, ["generate", "--format", "json"]).output)
    assert data["policy"]["Version"] == "2012-10-17"
    assert data["summary"] == {"errors": 0, "warnings": 0, "recommendations": 0}
    assert data["statements"][0]["explanations"][0]["source"].startswith("fmaws.yaml:")
    assert "candidate policy" in data["notice"]
    markdown = runner.invoke(app, ["generate", "--format", "markdown"]).output
    assert markdown.startswith("# fmaws generate report")
    assert "| Reason | Source | Confidence |" in markdown


def test_generate_output_option_and_strict_drops_discovered(project):
    root = project(EXAMPLE)
    result = runner.invoke(app, ["generate", "--strict", "--output", "policy.json"])
    assert result.exit_code == 0, result.output
    assert "ecommerce-agent-traces" not in (root / "policy.json").read_text()
    assert "--strict: 1 discovered resource(s) excluded" in result.output


def test_generate_strict_fails_on_warnings(project):
    root = project()
    (root / "fmaws.yaml").write_text(
        "resources:\n  sqs:\n    - queue: jobs\n      actions: [send]\n"
    )
    relaxed = runner.invoke(app, ["generate"])
    assert relaxed.exit_code == 0
    assert "Region unknown" in relaxed.output and "1 recommendation" in relaxed.output
    (root / "fmaws.yaml").write_text(
        "resources:\n  dynamodb:\n    - table: " + "t" * 6200 + "\n      actions: [read]\n"
    )
    assert runner.invoke(app, ["generate", "--strict"]).exit_code == 1


def test_generate_all_regions_and_region_flag(project):
    root = project(EXAMPLE)
    runner.invoke(app, ["generate", "--region", "eu-west-1"])
    assert (
        "arn:aws:sqs:eu-west-1:111122223333:order-processing"
        in (root / "generated-policy.json").read_text()
    )
    runner.invoke(app, ["generate", "--all-regions"])
    assert (
        "arn:aws:sqs:*:111122223333:order-processing"
        in (root / "generated-policy.json").read_text()
    )


def test_generate_without_any_resources_gives_next_steps(project):
    root = project()
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 0
    assert "No AWS resources were declared or detected" in result.output
    assert not (root / "generated-policy.json").exists()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("resources: [", "not valid YAML"),
        ("- just\n- a list\n", "mapping at the top level"),
        ("resources:\n  glacier:\n    - vault: x\n", "Unsupported service 'glacier'"),
        ("resources:\n  s3:\n    - bucket: 'Bad Bucket'\n", "Invalid S3 bucket name"),
        (
            "resources:\n  s3:\n    - bucket: good-bucket\n      prefixes: ['a*b/']\n",
            "wildcards inside",
        ),
        ("resources:\n  s3:\n    - bucket: good-bucket\n      acl: public\n", "resources.s3"),
        ("resources:\n  sqs:\n    - queue: q\n      actions: [admin]\n", "Unknown action 'admin'"),
        ("resources:\n  sqs:\n    - name: q\n", "needs 'queue'"),
        ("resources:\n  dynamodb:\n    - table: '*'\n", "may not contain wildcards"),
        ("aws:\n  account_id: '12'\n", "aws.account_id"),
        ("discovery:\n  paths: ['../../']\n", "outside the project"),
        (
            "resources:\n  dynamodb:\n    - table: !!python/object/apply:os.system ['id']\n",
            "not valid YAML",
        ),
    ],
)
def test_configuration_errors_exit_2_with_a_clear_message(project, content, message):
    root = project()
    (root / "fmaws.yaml").write_text(content)
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 2
    assert message in result.output
    assert "Traceback" not in result.output


def test_missing_explicit_config_exits_2(project):
    project()
    assert runner.invoke(app, ["generate", "--config", "nope.yaml"]).exit_code == 2


def test_statement_injection_through_resource_names_is_impossible(project):
    root = project()
    (root / "fmaws.yaml").write_text(
        'resources:\n  sqs:\n    - queue: \'q", "Action": "*\'\n      actions: [send]\n'
    )
    assert runner.invoke(app, ["generate"]).exit_code == 2


def test_validate_local_only_exit_codes_and_formats(project):
    root = project()
    (root / "clean.json").write_text(json.dumps(CLEAN))
    (root / "admin.json").write_text(json.dumps(ADMIN))
    (root / "broken.json").write_text("{nope")
    clean = runner.invoke(app, ["validate", "clean.json", "--local-only"])
    assert clean.exit_code == 0 and "Local validation: PASS" in clean.output
    admin = runner.invoke(app, ["validate", "admin.json", "--local-only"])
    assert admin.exit_code == 1
    assert "CRITICAL" in admin.output and "Fix:" in admin.output
    assert runner.invoke(app, ["validate", "broken.json", "--local-only"]).exit_code == 1
    assert runner.invoke(app, ["validate", "missing.json", "--local-only"]).exit_code == 2
    data = json.loads(
        runner.invoke(app, ["validate", "admin.json", "--local-only", "--format", "json"]).output
    )
    assert data["findings"][0]["id"] == "POLICY_FULL_ADMIN"
    assert set(data["findings"][0]) >= {
        "id", "severity", "category", "service", "resource", "title", "problem",
        "why_it_matters", "evidence", "recommendation", "remediation", "documentation_url",
        "confidence", "is_auto_fixable",
    }  # fmt: skip


def test_validate_reports_every_access_analyzer_finding(project, stubbed):
    root = project()
    (root / "clean.json").write_text(json.dumps(CLEAN))
    location = {
        "path": [{"value": "Statement"}, {"index": 0}, {"value": "Action"}],
        "span": {"start": {"line": 1, "column": 1, "offset": 1},
                 "end": {"line": 1, "column": 2, "offset": 2}},
    }  # fmt: skip

    def finding(kind, code):
        return {"findingType": kind, "issueCode": code, "findingDetails": f"details {code}",
                "learnMoreLink": "https://docs.aws.amazon.com/x", "locations": [location]}  # fmt: skip

    stubbed["accessanalyzer"].add_response(
        "validate_policy",
        {"findings": [finding("SUGGESTION", "EMPTY_SID")], "nextToken": "page2"},
        {"policyDocument": json.dumps(CLEAN), "policyType": "IDENTITY_POLICY"},
    )
    stubbed["accessanalyzer"].add_response(
        "validate_policy",
        {"findings": [finding("SECURITY_WARNING", "PASS_ROLE_WITH_STAR_IN_RESOURCE")]},
        {
            "policyDocument": json.dumps(CLEAN),
            "policyType": "IDENTITY_POLICY",
            "nextToken": "page2",
        },
    )
    result = runner.invoke(app, ["validate", "clean.json"])
    assert result.exit_code == 0, result.output
    assert "AWS IAM Access Analyzer: PASS" in result.output
    assert "details EMPTY_SID" in result.output
    assert "details PASS_ROLE_WITH_STAR_IN_RESOURCE" in result.output
    assert "Statement[0].Action" in result.output
    assert "1 warning" in result.output and "1 recommendation" in result.output


def test_access_analyzer_error_finding_fails_the_run(project, stubbed):
    root = project()
    (root / "clean.json").write_text(json.dumps(CLEAN))
    stubbed["accessanalyzer"].add_response(
        "validate_policy",
        {"findings": [{"findingType": "ERROR", "issueCode": "INVALID_ACTION",
                       "findingDetails": "bad", "learnMoreLink": "https://x", "locations": []}]},
    )  # fmt: skip
    result = runner.invoke(app, ["validate", "clean.json"])
    assert result.exit_code == 1
    assert "AWS IAM Access Analyzer: FAIL" in result.output


@pytest.mark.parametrize("code", ["AccessDeniedException", "ExpiredTokenException"])
def test_validate_auth_failure_exits_3_but_still_shows_local_result(project, stubbed, code):
    root = project()
    (root / "clean.json").write_text(json.dumps(CLEAN))
    stubbed["accessanalyzer"].add_client_error("validate_policy", service_error_code=code)
    result = runner.invoke(app, ["validate", "clean.json"])
    assert result.exit_code == 3
    assert "Local validation: PASS" in result.output
    assert "--local-only" in result.output


def test_throttling_is_a_runtime_error_not_an_auth_error(project, stubbed):
    root = project()
    (root / "clean.json").write_text(json.dumps(CLEAN))
    stubbed["accessanalyzer"].add_client_error(
        "validate_policy", service_error_code="ThrottlingException"
    )
    result = runner.invoke(app, ["validate", "clean.json"])
    assert result.exit_code == 2 and "throttled" in result.output


def test_generate_validate_uses_sts_account_and_access_analyzer(project, stubbed):
    root = project()
    (root / "fmaws.yaml").write_text(
        "aws:\n  region: us-east-1\nresources:\n  sqs:\n    - queue: jobs\n      actions: [send]\n"
    )
    stubbed["sts"].add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dev", "UserId": "U"},
    )
    stubbed["accessanalyzer"].add_response("validate_policy", {"findings": []})
    result = runner.invoke(app, ["generate", "--validate"])
    assert result.exit_code == 0, result.output
    assert "AWS IAM Access Analyzer: PASS" in result.output
    assert "Account: ********9012" in result.output
    assert "arn:aws:sqs:us-east-1:123456789012:jobs" in (root / "generated-policy.json").read_text()
    stubbed["sts"].assert_no_pending_responses()
    stubbed["accessanalyzer"].assert_no_pending_responses()


def test_generate_validate_without_credentials_exits_3(project, monkeypatch):
    root = project()
    (root / "fmaws.yaml").write_text(
        "resources:\n  sqs:\n    - queue: jobs\n      actions: [send]\n"
    )
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    result = runner.invoke(app, ["generate", "--validate", "--region", "us-east-1"])
    assert result.exit_code == 3
    assert "No usable AWS credentials" in result.output


def test_unknown_profile_exits_3(project):
    root = project()
    (root / "fmaws.yaml").write_text(
        "resources:\n  sqs:\n    - queue: jobs\n      actions: [send]\n"
    )
    result = runner.invoke(app, ["generate", "--profile", "does-not-exist"])
    assert result.exit_code == 3 and "does-not-exist" in result.output


def test_doctor_reports_identity_with_masked_account(project, stubbed):
    project()
    stubbed["sts"].add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dev", "UserId": "U"},
    )
    stubbed["accessanalyzer"].add_response("validate_policy", {"findings": []})
    result = runner.invoke(app, ["doctor", "--region", "us-east-1"])
    assert result.exit_code == 0, result.output
    assert "arn:aws:iam::********9012:user/dev" in result.output
    assert "123456789012" not in result.output
    assert "OK    access-analyzer:ValidatePolicy" in result.output
    assert "AKIA" not in result.output and "wJalr" not in result.output


def test_doctor_partial_permissions_is_a_warning_not_a_failure(project, stubbed):
    project()
    stubbed["sts"].add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dev", "UserId": "U"},
    )
    stubbed["accessanalyzer"].add_client_error(
        "validate_policy", service_error_code="AccessDeniedException"
    )
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "WARN  access-analyzer:ValidatePolicy" in result.output
    assert "WARN  Region" in result.output


def test_doctor_without_credentials_exits_3(project, monkeypatch):
    project()
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 3
    assert "FAIL  Credentials" in result.output and "aws configure sso" in result.output


def test_only_read_only_aws_operations_are_called_outside_the_audit():
    import re

    # audit and observe have their own allow-lists, tested in test_audit.py and test_observe.py.
    files = [
        p
        for p in (REPO / "src" / "fmaws").rglob("*.py")
        if "audit" not in p.parts and p.name != "observe.py"
    ]
    source = "\n".join(p.read_text() for p in files)
    called = set(
        re.findall(r"\.(get_caller_identity|validate_policy|[a-z_]+)\(\*\*kwargs\)", source)
    )
    called |= set(re.findall(r'client\("[a-z]+"\)\.([a-z_]+)\(', source))
    assert called == {"get_caller_identity", "validate_policy"}
    assert set(re.findall(r'\.client\(\s*"([a-z0-9-]+)"', source)) == {"sts", "accessanalyzer"}


def test_explain_generated_and_existing_policy(project):
    root = project(EXAMPLE)
    generated = runner.invoke(app, ["explain"])
    assert generated.exit_code == 0
    assert "Reason:" in generated.output and "Source: fmaws.yaml:" in generated.output
    assert not (root / "generated-policy.json").exists()
    (root / "p.json").write_text(json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["dynamodb:ListTables", "sqs:SendMessage", "ec2:RunInstances"],
             "Resource": "*"}
        ],
    }))  # fmt: skip
    existing = runner.invoke(app, ["explain", "p.json"]).output
    assert 'dynamodb:ListTables: requires Resource "*"' in existing
    assert "sqs:SendMessage: send access to a SQS queue" in existing
    assert "ec2:RunInstances: not in the fmaws service catalog" in existing


def test_secrets_in_project_never_reach_any_cli_output(project):
    root = project(FIXTURES / "order-pipeline")
    outputs = [
        runner.invoke(app, ["generate", *args]).output
        for args in ([], ["--explain"], ["--format", "json"], ["--format", "markdown"])
    ]
    outputs.append((root / "generated-policy.json").read_text())
    for output in outputs:
        assert "sk_live" not in output and "correct-horse" not in output


def test_redaction_is_applied_to_everything_printed():
    from fmaws.utils.redact import redact

    text = redact("key AKIAIOSFODNN7EXAMPLE password=hunter2 aws_secret_access_key: abc/def")
    assert "AKIAIOSFODNN7EXAMPLE" not in text and "hunter2" not in text and "abc/def" not in text
    arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/api-??????"
    assert redact(arn) == arn


def test_malformed_region_is_a_configuration_error(project):
    root = project()
    (root / "fmaws.yaml").write_text(
        "resources:\n  sqs:\n    - queue: jobs\n      actions: [send]\n"
    )
    result = runner.invoke(app, ["generate", "--region", "us-east-1:999999999999"])
    assert result.exit_code == 2 and "Invalid AWS region" in result.output
    assert not (root / "generated-policy.json").exists()


def test_region_hints_from_project_files_cannot_inject_arn_fields(project):
    root = project()
    (root / "fmaws.yaml").write_text(
        "resources:\n  sqs:\n    - queue: jobs\n      actions: [send]\n"
    )
    (root / "main.tf").write_text('provider "aws" {\n  region = "us-east-1:999999999999"\n}\n')
    (root / "serverless.yml").write_text("service: x\nprovider:\n  region: eu-west-1/*\n")
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 0, result.output
    policy = (root / "generated-policy.json").read_text()
    assert "arn:aws:sqs:*:*:jobs" in policy and "999999999999" not in policy
