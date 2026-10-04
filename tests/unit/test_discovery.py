import json
import os

import pytest

from fmaws.discovery.base import discover
from fmaws.discovery.merge import merge_requirements
from fmaws.errors import ConfigError
from fmaws.models.requirement import Confidence, ResourceRequirement, SourceRef


def found(detection):
    return {(r.service, r.resource): r for r in detection.requirements}


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_env_file_keeps_resources_and_drops_everything_else(tmp_path):
    write(
        tmp_path,
        ".env",
        "AWS_REGION=ap-south-1\n"
        "export ASSETS_BUCKET=ecommerce-assets\n"
        'DYNAMODB_TABLE="customers"\n'
        "DB_SECRET_NAME=prod/ecommerce/api\n"
        "BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0\n"
        "ORDERS_QUEUE_URL=https://sqs.ap-south-1.amazonaws.com/111122223333/order-processing\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "DB_PASSWORD=hunter2hunter2\n"
        "OAUTH_CLIENT_SECRET_ID=abc123\n"
        "SQL_TABLE=users\n",
    )
    detection = discover(tmp_path)
    resources = found(detection)
    assert set(resources) == {
        ("s3", "ecommerce-assets"),
        ("dynamodb", "customers"),
        ("secretsmanager", "prod/ecommerce/api"),
        ("bedrock", "anthropic.claude-3-haiku-20240307-v1:0"),
        ("sqs", "arn:aws:sqs:ap-south-1:111122223333:order-processing"),
    }
    assert resources[("s3", "ecommerce-assets")].source == SourceRef(file=".env", line=2)
    assert resources[("s3", "ecommerce-assets")].confidence is Confidence.MEDIUM
    assert not resources[("s3", "ecommerce-assets")].intent_confirmed
    assert "ap-south-1" in detection.regions and detection.accounts == ["111122223333"]
    dumped = json.dumps([r.model_dump(mode="json") for r in detection.requirements])
    assert "wJalr" not in dumped and "hunter2" not in dumped and "abc123" not in dumped


def test_arns_in_any_text_file_and_wildcard_arns_ignored(tmp_path):
    write(
        tmp_path,
        "config/app.yaml",
        "topic: arn:aws:sns:us-east-1:111122223333:order-events\n"
        "bucket: arn:aws:s3:::report-bucket/reports/\n"
        "role: arn:aws:iam::111122223333:role/app\n"
        "all: arn:aws:sqs:us-east-1:111122223333:*\n",
    )
    resources = found(discover(tmp_path))
    assert set(resources) == {
        ("sns", "arn:aws:sns:us-east-1:111122223333:order-events"),
        ("s3", "report-bucket"),
    }


def test_standalone_policy_documents_are_not_evidence(tmp_path):
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sqs:SendMessage",
         "Resource": "arn:aws:sqs:us-east-1:111122223333:orders"}]}  # fmt: skip
    write(tmp_path, "policy.json", json.dumps(policy))
    assert discover(tmp_path).requirements == []


def test_cloudformation_with_intrinsics_and_generated_names(tmp_path):
    write(
        tmp_path,
        "template.yaml",
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Transform: AWS::Serverless-2016-10-31\n"
        "Resources:\n"
        "  Assets:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: image-uploads\n"
        "  Generated:\n"
        "    Type: AWS::S3::Bucket\n"
        "  Named:\n"
        "    Type: AWS::SQS::Queue\n"
        "    Properties:\n"
        "      QueueName: !Sub '${AWS::StackName}-jobs'\n"
        "  Worker:\n"
        "    Type: AWS::Serverless::Function\n"
        "    Properties:\n"
        "      Environment:\n"
        "        Variables:\n"
        "          OUTPUT_BUCKET: image-thumbnails\n"
        "          QUEUE_ARN: !GetAtt Named.Arn\n",
    )
    detection = discover(tmp_path)
    resources = found(detection)
    assert set(resources) == {("s3", "image-uploads"), ("s3", "image-thumbnails")}
    assert resources[("s3", "image-uploads")].confidence is Confidence.LOW
    assert resources[("s3", "image-uploads")].source.line == 7
    assert any("2 resource(s) have names generated" in n for n in detection.notes)


def test_cdk_synthesized_json_template(tmp_path):
    template = {"Resources": {"Table1": {"Type": "AWS::DynamoDB::Table",
                                         "Properties": {"TableName": "tenants"}}}}  # fmt: skip
    write(tmp_path, "cdk.out/App.template.json", json.dumps(template))
    assert set(found(discover(tmp_path))) == {("dynamodb", "tenants")}


def test_terraform_static_names_and_unresolved_expressions(tmp_path):
    write(
        tmp_path,
        "terraform/main.tf",
        'provider "aws" {\n  region = "eu-west-1"\n}\n'
        'resource "aws_s3_bucket" "assets" {\n  bucket = "tf-assets-bucket"\n}\n'
        'resource "aws_sqs_queue" "jobs" {\n  name = "${var.env}-jobs"\n}\n'
        'resource "aws_dynamodb_table" "orders" {\n  name = "orders"\n  hash_key = "id"\n}\n'
        'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n'
        '  environment {\n    variables = {\n      REPORTS_BUCKET = "tf-reports-bucket"\n    }\n  }\n}\n',
    )
    detection = discover(tmp_path)
    resources = found(detection)
    assert set(resources) == {
        ("s3", "tf-assets-bucket"),
        ("dynamodb", "orders"),
        ("s3", "tf-reports-bucket"),
    }
    assert resources[("s3", "tf-assets-bucket")].source == SourceRef(
        file="terraform/main.tf", line=5
    )
    assert detection.regions == ["eu-west-1"]
    assert any("1 resource name(s) use variables" in n for n in detection.notes)


def test_serverless_and_docker(tmp_path):
    write(
        tmp_path,
        "serverless.yml",
        "service: orders\nprovider:\n  name: aws\n  region: us-west-2\n  environment:\n"
        "    UPLOAD_BUCKET: sls-uploads\nfunctions:\n  worker:\n    handler: h.main\n"
        "    environment:\n      DDB_TABLE: sls-orders\nresources:\n  Resources:\n    Topic:\n"
        "      Type: AWS::SNS::Topic\n      Properties:\n        TopicName: sls-events\n",
    )
    write(
        tmp_path,
        "docker-compose.yml",
        "services:\n  app:\n    environment:\n      - CACHE_BUCKET=compose-cache\n"
        "  worker:\n    environment:\n      APP_LOG_GROUP: /app/worker\n",
    )
    write(tmp_path, "Dockerfile", "FROM scratch\nENV DATA_BUCKET=docker-data\nENV TOKEN=sekrit\n")
    resources = found(discover(tmp_path))
    assert set(resources) == {
        ("s3", "sls-uploads"), ("dynamodb", "sls-orders"), ("sns", "sls-events"),
        ("s3", "compose-cache"), ("logs", "/app/worker"), ("s3", "docker-data"),
    }  # fmt: skip


def test_sdk_usage_infers_intents_from_calls(tmp_path):
    write(
        tmp_path,
        "src/app.py",
        "import boto3\ns3 = boto3.client('s3')\n"
        "s3.get_object(Bucket='sdk-images', Key=k)\n"
        "s3.put_object(Bucket='sdk-images', Key=k, Body=b)\n"
        "bedrock.invoke_model(modelId='anthropic.claude-3-haiku-20240307-v1:0', body=b)\n",
    )
    write(
        tmp_path,
        "src/handler.ts",
        'import { GetItemCommand } from "@aws-sdk/client-dynamodb";\n'
        'await client.send(new GetItemCommand({ TableName: "sdk-sessions", Key: key }));\n',
    )
    resources = found(discover(tmp_path))
    bucket = resources[("s3", "sdk-images")]
    assert bucket.intents == ("read", "write") and bucket.intent_confirmed
    assert bucket.confidence is Confidence.MEDIUM and bucket.source.line == 3
    assert resources[("bedrock", "anthropic.claude-3-haiku-20240307-v1:0")].intents == ("invoke",)
    assert resources[("dynamodb", "sdk-sessions")].intents == ("read",)


def test_non_aws_source_is_ignored(tmp_path):
    write(tmp_path, "src/db.py", "cursor.execute(q, TableName='users')\n")
    assert discover(tmp_path).requirements == []


def test_malformed_and_malicious_files_are_skipped_not_fatal(tmp_path):
    write(
        tmp_path, "template.yaml", "Resources:\n  X:\n    Type: AWS::S3::Bucket\n  bad: [unclosed\n"
    )
    write(
        tmp_path,
        "infra/evil.yaml",
        "Resources:\n  X:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      BucketName: !!python/object/apply:os.system ['touch pwned']\n",
    )
    write(tmp_path, "terraform/broken.tf", 'resource "aws_s3_bucket" "x" {\n  bucket = \n')
    write(tmp_path, "ok/.env", "DATA_BUCKET=still-found\n")
    detection = discover(tmp_path)
    assert set(found(detection)) == {("s3", "still-found")}
    assert len([n for n in detection.notes if n.startswith("Skipped")]) == 3
    assert not (tmp_path / "pwned").exists()


def test_terraform_expressions_are_never_evaluated(tmp_path):
    write(
        tmp_path,
        "main.tf",
        'resource "aws_s3_bucket" "x" {\n  bucket = file("/etc/passwd")\n}\n'
        'data "external" "run" {\n  program = ["sh", "-c", "touch pwned"]\n}\n',
    )
    assert discover(tmp_path).requirements == []
    assert not (tmp_path / "pwned").exists()


def test_walker_skips_vendor_dirs_big_files_and_escaping_symlinks(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    write(outside, ".env", "SECRET_BUCKET=outside-bucket\n")
    write(project, "node_modules/pkg/.env", "X_BUCKET=vendored-bucket\n")
    write(project, "big.env", "Y_BUCKET=big-file-bucket\n" + "#" * 2_100_000)
    write(project, ".env", "Z_BUCKET=inside-bucket\n")
    os.symlink(outside / ".env", project / "linked.env")
    os.symlink(outside, project / "linkdir")
    detection = discover(project)
    assert set(found(detection)) == {("s3", "inside-bucket")}
    assert any("larger than 2 MB" in n for n in detection.notes)
    assert any("symlink points outside" in n for n in detection.notes)


def test_discovery_paths_cannot_escape_the_project(tmp_path):
    with pytest.raises(ConfigError, match="outside the project"):
        discover(tmp_path, paths=["../.."])


def test_paths_exclude_and_detector_selection(tmp_path):
    write(tmp_path, "a/.env", "A_BUCKET=bucket-aaa\n")
    excluded = write(tmp_path, "b/.env", "B_BUCKET=bucket-bbb\n")
    assert set(found(discover(tmp_path, paths=["a"]))) == {("s3", "bucket-aaa")}
    assert set(found(discover(tmp_path, exclude=[excluded]))) == {("s3", "bucket-aaa")}
    assert discover(tmp_path, enabled=["terraform"]).requirements == []
    with pytest.raises(ConfigError, match="Unknown detector 'terrafrom'"):
        discover(tmp_path, enabled=["terrafrom"])


def req(service, resource, intents, confidence, file, confirmed=True):
    return ResourceRequirement(
        service=service, resource=resource, intents=intents, confidence=confidence,
        source=SourceRef(file=file, line=1), reason="r", intent_confirmed=confirmed,
    )  # fmt: skip


def test_merge_declared_wins_and_evidence_is_folded():
    declared = [req("sqs", "orders", ("send",), Confidence.HIGH, "fmaws.yaml")]
    discovered = [
        req(
            "sqs",
            "arn:aws:sqs:us-east-1:111122223333:orders",
            ("read",),
            Confidence.MEDIUM,
            ".env",
            False,
        ),
        req("dynamodb", "customers", ("read",), Confidence.LOW, "main.tf", False),
        req("dynamodb", "customers", ("write",), Confidence.MEDIUM, "app.py"),
        req(
            "sns",
            "arn:aws:sns:us-east-1:111122223333:events",
            ("publish",),
            Confidence.MEDIUM,
            ".env",
            False,
        ),
        req("sns", "events", ("publish",), Confidence.LOW, "main.tf", False),
    ]
    merged = merge_requirements(declared, discovered)
    assert [(r.service, r.resource, r.intents, r.confidence) for r in merged] == [
        ("sqs", "orders", ("send",), Confidence.HIGH),
        ("dynamodb", "customers", ("write",), Confidence.MEDIUM),
        ("sns", "arn:aws:sns:us-east-1:111122223333:events", ("publish",), Confidence.MEDIUM),
    ]
    assert merged[1].intent_confirmed and not merged[2].intent_confirmed
