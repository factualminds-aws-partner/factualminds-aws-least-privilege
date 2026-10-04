"""Built-in detectors. Static analysis only: files are parsed, never executed.

Each detector is registered at import time. A new detector is one more class and one
``register()`` call, here or in any module imported before discovery runs.
"""

import json
import re
from pathlib import Path
from typing import Any

import hcl2
import yaml

from fmaws.discovery.base import Detection, register
from fmaws.models.requirement import Confidence, ResourceRequirement, SourceRef
from fmaws.policy import catalog, s3
from fmaws.policy.arns import NAME_RE, parse_arn
from fmaws.utils.text import find_line, line_at

_ARN_RE = re.compile(
    r"arn:(?:aws|aws-cn|aws-us-gov):[a-z0-9-]+:[a-z0-9-]*:(?:\d{12})?:[^\s\"'`,;<>()\[\]{}\\]+"
)
_SQS_URL_RE = re.compile(
    r"https://sqs\.([a-z0-9-]+)\.amazonaws\.com/(\d{12})/([A-Za-z0-9_-]+(?:\.fifo)?)"
)
_S3_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-cn|aws-us-gov):s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(/.*)?$"
)
_BEDROCK_MODEL_RE = re.compile(
    r"(?:(?:us|eu|apac|global)\.)?(?:anthropic|amazon|meta|mistral|cohere|ai21|stability|deepseek)"
    r"\.[a-z0-9][a-z0-9.:-]+"
)
_SOURCE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs",
}  # fmt: skip
_TEXT_SUFFIXES = _SOURCE_SUFFIXES | {
    ".env", ".yml", ".yaml", ".json", ".tf", ".tfvars", ".toml", ".ini", ".properties", ".conf",
    ".sh",
}  # fmt: skip


def _is_env_file(path: Path) -> bool:
    return path.name == ".env" or path.name.startswith(".env.") or path.suffix == ".env"


def _requirement(
    service: str,
    resource: str,
    file: str,
    line: int | None,
    reason: str,
    confidence: Confidence,
    intents: tuple[str, ...] = (),
) -> ResourceRequirement:
    defaults = s3.DEFAULT_INTENTS if service == "s3" else catalog.get(service).default_intents
    return ResourceRequirement(
        service=service,
        resource=resource,
        intents=intents or defaults,
        confidence=confidence,
        source=SourceRef(file=file, line=line),
        reason=reason,
        intent_confirmed=bool(intents),
    )


def _static(value: Any) -> str | None:
    """A literal string, or None when the value is computed (interpolation, intrinsic, etc.)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not NAME_RE.fullmatch(value):
        return None
    return str(value)


# --------------------------------------------------------------------------- ARNs and URLs


class ArnDetector:
    """Literal ARNs and SQS queue URLs anywhere in configuration, infrastructure or source."""

    name = "arn"

    def matches(self, path: Path) -> bool:
        return path.suffix in _TEXT_SUFFIXES or _is_env_file(path) or path.name == "Dockerfile"

    def detect(self, relative_path: str, text: str) -> Detection:
        result = Detection()
        if relative_path.endswith(".json") and _is_policy_document(text):
            # A standalone IAM policy describes what is granted, not what the application uses.
            return result
        for match in _SQS_URL_RE.finditer(text):
            region, account, name = match.groups()
            arn = f"arn:aws:sqs:{region}:{account}:{name}"
            self._add(result, arn, relative_path, text, match.start(), "SQS queue URL")
        for match in _ARN_RE.finditer(text):
            self._add(
                result, match.group(0).rstrip(".:"), relative_path, text, match.start(), "ARN"
            )
        return result

    def _add(
        self, result: Detection, arn: str, file: str, text: str, offset: int, kind: str
    ) -> None:
        if "*" in arn or "?" in arn or "$" in arn:
            return
        line = line_at(text, offset)
        bucket = _S3_ARN_RE.match(arn)
        if bucket:
            result.requirements.append(
                _requirement(
                    "s3",
                    bucket.group(1),
                    file,
                    line,
                    f"{kind} referenced in {file}",
                    Confidence.MEDIUM,
                )
            )
            return
        for definition in catalog.CATALOG.values():
            parsed = parse_arn(definition, arn)
            if parsed is None:
                continue
            result.requirements.append(
                _requirement(
                    definition.service,
                    arn,
                    file,
                    line,
                    f"{kind} referenced in {file}",
                    Confidence.MEDIUM,
                )
            )
            if parsed.get("region"):
                result.regions.append(parsed["region"])
            if parsed.get("account"):
                result.accounts.append(parsed["account"])
            return


def _is_policy_document(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return False
    return isinstance(data, dict) and "Statement" in data


# --------------------------------------------------------------------------- environment


def env_pairs(file: str, pairs: list[tuple[str, Any, int | None]], origin: str) -> Detection:
    """Resource references in environment-style key/value pairs.

    Only values that look like AWS resource identifiers under a telling key are kept. Every
    other value (credentials, passwords, tokens) is dropped here and never stored.
    """
    result = Detection()

    def add(service: str, value: str, line: int | None) -> None:
        result.requirements.append(
            _requirement(
                service, value, file, line, f"Referenced by {origin} in {file}", Confidence.MEDIUM
            )
        )

    for key, raw, line in pairs:
        value = _static(raw)
        if value is None or value.startswith(("arn:", "http")):
            continue  # ARNs and URLs are the ArnDetector's job
        upper = key.upper()
        if upper in ("AWS_REGION", "AWS_DEFAULT_REGION"):
            if re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", value):
                result.regions.append(value)
        elif "BUCKET" in upper and s3.BUCKET_RE.fullmatch(value):
            add("s3", value, line)
        elif "TABLE" in upper and ("DYNAMO" in upper or "DDB" in upper):
            add("dynamodb", value, line)
        elif "QUEUE" in upper and ("SQS" in upper or upper.endswith("QUEUE_NAME")):
            add("sqs", value, line)
        elif re.search(r"SECRETS?(_?MANAGER)?_(NAME|ID)$", upper) and not re.search(
            r"CLIENT|ACCESS|KEY", upper
        ):
            add("secretsmanager", value, line)
        elif "LOG_GROUP" in upper:
            add("logs", value, line)
        elif "EVENT_BUS" in upper:
            add("eventbridge", value, line)
        elif (
            "KMS" in upper
            and "KEY" in upper
            and re.fullmatch(r"alias/[\w/-]+|[0-9a-f-]{36}", value)
        ):
            add("kms", value, line)
        elif _BEDROCK_MODEL_RE.fullmatch(value) and ("MODEL" in upper or "BEDROCK" in upper):
            add("bedrock", value, line)
    return result


def _parse_env(text: str) -> list[tuple[str, Any, int | None]]:
    pairs: list[tuple[str, Any, int | None]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
        if match:
            pairs.append((match.group(1), match.group(2).split(" #")[0].strip(), number))
    return pairs


class EnvDetector:
    name = "env"

    def matches(self, path: Path) -> bool:
        return _is_env_file(path)

    def detect(self, relative_path: str, text: str) -> Detection:
        return env_pairs(relative_path, _parse_env(text), "environment variable")


# --------------------------------------------------------------------------- CloudFormation


class _InertLoader(yaml.SafeLoader):
    """SafeLoader that turns CloudFormation short-form tags (!Ref, !Sub, ...) into ``None``."""


def _inert(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> None:
    return None


_InertLoader.add_multi_constructor("!", _inert)


def load_template(text: str, json_only: bool = False) -> Any:
    if json_only:
        return json.loads(text)
    return yaml.load(text, Loader=_InertLoader)  # noqa: S506  _InertLoader is a SafeLoader


# CloudFormation resource type -> (service, property holding the physical name)
_CFN_TYPES = {
    "AWS::S3::Bucket": ("s3", "BucketName"),
    "AWS::DynamoDB::Table": ("dynamodb", "TableName"),
    "AWS::DynamoDB::GlobalTable": ("dynamodb", "TableName"),
    "AWS::Serverless::SimpleTable": ("dynamodb", "TableName"),
    "AWS::SQS::Queue": ("sqs", "QueueName"),
    "AWS::SNS::Topic": ("sns", "TopicName"),
    "AWS::SecretsManager::Secret": ("secretsmanager", "Name"),
    "AWS::Logs::LogGroup": ("logs", "LogGroupName"),
    "AWS::Events::EventBus": ("eventbridge", "Name"),
    "AWS::KMS::Alias": ("kms", "AliasName"),
}
_CFN_FUNCTIONS = {"AWS::Lambda::Function", "AWS::Serverless::Function"}


def cfn_resources(file: str, text: str, resources: Any, origin: str) -> Detection:
    result = Detection()
    if not isinstance(resources, dict):
        return result
    generated = 0
    for logical_id, resource in sorted(resources.items(), key=lambda kv: str(kv[0])):
        if not isinstance(resource, dict):
            continue
        kind = resource.get("Type")
        properties = resource.get("Properties")
        properties = properties if isinstance(properties, dict) else {}
        if kind in _CFN_FUNCTIONS:
            environment = properties.get("Environment")
            variables = environment.get("Variables") if isinstance(environment, dict) else None
            if isinstance(variables, dict):
                pairs = [(str(k), v, find_line(text, str(k))) for k, v in variables.items()]
                result.merge(env_pairs(file, pairs, f"Lambda function {logical_id}"))
            continue
        if kind not in _CFN_TYPES:
            continue
        service, name_property = _CFN_TYPES[kind]
        name = _static(properties.get(name_property))
        if name is None or (service == "s3" and not s3.BUCKET_RE.fullmatch(name)):
            generated += 1
            continue
        result.requirements.append(
            _requirement(
                service,
                name,
                file,
                find_line(text, name),
                f"{origin} resource {logical_id} ({kind})",
                Confidence.LOW,
            )
        )
    if generated:
        result.notes.append(
            f"{file}: {generated} resource(s) have names generated at deploy time. "
            "Declare them in fmaws.yaml once the physical names are known."
        )
    return result


class CloudFormationDetector:
    """CloudFormation, SAM and synthesized CDK templates."""

    name = "cloudformation"

    def matches(self, path: Path) -> bool:
        return path.suffix in (".yml", ".yaml", ".json", ".template")

    def detect(self, relative_path: str, text: str) -> Detection:
        if "Resources" not in text or "AWS::" not in text:
            return Detection()
        template = load_template(text, json_only=relative_path.endswith(".json"))
        if not isinstance(template, dict):
            return Detection()
        return cfn_resources(relative_path, text, template.get("Resources"), "CloudFormation")


# --------------------------------------------------------------------------- Serverless Framework


class ServerlessDetector:
    name = "serverless"

    def matches(self, path: Path) -> bool:
        return path.name in ("serverless.yml", "serverless.yaml")

    def detect(self, relative_path: str, text: str) -> Detection:
        result = Detection()
        config = load_template(text)
        if not isinstance(config, dict):
            return result
        provider = config.get("provider")
        environments: list[tuple[str, Any]] = []
        if isinstance(provider, dict):
            environments.append(("provider", provider.get("environment")))
            region = _static(provider.get("region"))
            if region:
                result.regions.append(region)
        functions = config.get("functions")
        if isinstance(functions, dict):
            for name, function in functions.items():
                if isinstance(function, dict):
                    environments.append((f"function {name}", function.get("environment")))
        for origin, environment in environments:
            if isinstance(environment, dict):
                pairs = [(str(k), v, find_line(text, str(k))) for k, v in environment.items()]
                result.merge(env_pairs(relative_path, pairs, f"Serverless {origin} environment"))
        extra = config.get("resources")
        if isinstance(extra, dict):
            result.merge(cfn_resources(relative_path, text, extra.get("Resources"), "Serverless"))
        return result


# --------------------------------------------------------------------------- Terraform

# Terraform resource type -> (service, argument holding the physical name)
_TF_TYPES = {
    "aws_s3_bucket": ("s3", "bucket"),
    "aws_dynamodb_table": ("dynamodb", "name"),
    "aws_sqs_queue": ("sqs", "name"),
    "aws_sns_topic": ("sns", "name"),
    "aws_secretsmanager_secret": ("secretsmanager", "name"),
    "aws_cloudwatch_log_group": ("logs", "name"),
    "aws_cloudwatch_event_bus": ("eventbridge", "name"),
    "aws_kms_alias": ("kms", "name"),
}


def _unquote(value: Any) -> Any:
    """python-hcl2 >= 5 keeps the quotes of labels and string literals."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _first(value: Any) -> Any:
    """python-hcl2 < 5 wraps attribute values and nested blocks in single-element lists."""
    return value[0] if isinstance(value, list) and len(value) == 1 else value


class TerraformDetector:
    name = "terraform"

    def matches(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def detect(self, relative_path: str, text: str) -> Detection:
        result = Detection()
        parsed = hcl2.loads(text)
        unresolved = 0
        for block in parsed.get("resource", []):
            for raw_type, instances in block.items():
                kind = _unquote(raw_type)
                if not isinstance(instances, dict):
                    continue
                for raw_label, body in instances.items():
                    label = _unquote(raw_label)
                    body = _first(body)
                    if not isinstance(body, dict):
                        continue
                    if kind == "aws_lambda_function":
                        environment = _first(body.get("environment"))
                        variables = (
                            _first(environment.get("variables"))
                            if isinstance(environment, dict)
                            else None
                        )
                        if isinstance(variables, dict):
                            pairs = [
                                (
                                    str(_unquote(k)),
                                    _unquote(_first(v)),
                                    find_line(text, str(_unquote(k))),
                                )
                                for k, v in variables.items()
                            ]
                            result.merge(
                                env_pairs(relative_path, pairs, f"Lambda function {label}")
                            )
                        continue
                    if kind not in _TF_TYPES:
                        continue
                    service, argument = _TF_TYPES[kind]
                    name = _static(_unquote(_first(body.get(argument))))
                    if name is None or (service == "s3" and not s3.BUCKET_RE.fullmatch(name)):
                        unresolved += 1
                        continue
                    result.requirements.append(
                        _requirement(
                            service,
                            name,
                            relative_path,
                            find_line(text, f'"{name}"'),
                            f"Terraform resource {kind}.{label}",
                            Confidence.LOW,
                        )
                    )
        for block in parsed.get("provider", []):
            aws = _first(block.get("aws") or block.get('"aws"'))
            region = _static(_unquote(_first(aws.get("region")))) if isinstance(aws, dict) else None
            if region:
                result.regions.append(region)
        if unresolved:
            result.notes.append(
                f"{relative_path}: {unresolved} resource name(s) use variables or expressions and "
                "were not resolved. Declare them in fmaws.yaml."
            )
        return result


# --------------------------------------------------------------------------- Docker


class DockerDetector:
    """Environment of docker-compose services and Dockerfile ENV instructions."""

    name = "docker"

    def matches(self, path: Path) -> bool:
        name = path.name
        return (
            name == "Dockerfile"
            or name.startswith("Dockerfile.")
            or re.fullmatch(r"(docker-)?compose(\..+)?\.ya?ml", name) is not None
        )

    def detect(self, relative_path: str, text: str) -> Detection:
        if "Dockerfile" in Path(relative_path).name:
            pairs: list[tuple[str, Any, int | None]] = []
            for number, line in enumerate(text.splitlines(), 1):
                match = re.match(r"^\s*ENV\s+([A-Za-z_][A-Za-z0-9_]*)[=\s]\s*(\S+)", line)
                if match:
                    pairs.append((match.group(1), match.group(2), number))
            return env_pairs(relative_path, pairs, "Dockerfile ENV")

        result = Detection()
        compose = yaml.safe_load(text)
        services = compose.get("services") if isinstance(compose, dict) else None
        if not isinstance(services, dict):
            return result
        for name, service in sorted(services.items(), key=lambda kv: str(kv[0])):
            environment = service.get("environment") if isinstance(service, dict) else None
            items: list[tuple[str, Any]] = []
            if isinstance(environment, dict):
                items = [(str(k), v) for k, v in environment.items()]
            elif isinstance(environment, list):
                items = [tuple(str(e).split("=", 1)) for e in environment if "=" in str(e)]  # type: ignore[misc]
            pairs = [(k, v, find_line(text, k)) for k, v in items]
            result.merge(env_pairs(relative_path, pairs, f"compose service {name}"))
        return result


# --------------------------------------------------------------------------- SDK usage

# service -> (regex capturing a literal resource name, {normalized operation name: intent})
_SDK: dict[str, tuple[re.Pattern[str], dict[str, str]]] = {
    "s3": (
        re.compile(r"\bBucket[\"']?\s*[=:]\s*[\"']([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])[\"']"),
        {
            "getobject": "read", "downloadfile": "read", "downloadfileobj": "read",
            "headobject": "read", "putobject": "write", "uploadfile": "write",
            "uploadfileobj": "write", "createmultipartupload": "write",
            "deleteobject": "delete", "deleteobjects": "delete",
            "listobjectsv2": "list", "listobjects": "list",
        },
    ),
    "dynamodb": (
        re.compile(r"\bTableName[\"']?\s*[=:]\s*[\"']([A-Za-z0-9_.-]{3,255})[\"']"),
        {
            "getitem": "read", "batchgetitem": "read", "query": "read", "scan": "read",
            "putitem": "write", "updateitem": "write", "batchwriteitem": "write",
            "deleteitem": "delete",
        },
    ),
    "secretsmanager": (
        re.compile(r"\bSecretId[\"']?\s*[=:]\s*[\"']([A-Za-z0-9/_+=.@-]+)[\"']"),
        {"getsecretvalue": "read", "putsecretvalue": "write"},
    ),
    "lambda": (
        re.compile(r"\bFunctionName[\"']?\s*[=:]\s*[\"']([A-Za-z0-9_-]+)[\"']"),
        {"invoke": "invoke", "invokecommand": "invoke"},
    ),
    "bedrock": (
        re.compile(r"\bmodelId[\"']?\s*[=:]\s*[\"']([A-Za-z0-9.:-]+)[\"']", re.IGNORECASE),
        {
            "invokemodel": "invoke", "invokemodelwithresponsestream": "invoke",
            "converse": "invoke", "conversestream": "invoke",
        },
    ),
}  # fmt: skip
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*?)(?:Command)?\s*\(")


class SdkDetector:
    """Literal resource names passed to AWS SDK calls, with intents inferred from the calls."""

    name = "sdk"

    def matches(self, path: Path) -> bool:
        return path.suffix in _SOURCE_SUFFIXES

    def detect(self, relative_path: str, text: str) -> Detection:
        result = Detection()
        if not re.search(r"boto3|aws-sdk|awssdk|aws_sdk|AWSSDK|software\.amazon", text):
            return result
        calls = {m.group(1).replace("_", "").lower() for m in _CALL_RE.finditer(text)}
        for service, (pattern, operations) in _SDK.items():
            intents = tuple(sorted({operations[c] for c in calls if c in operations}))
            first_seen: dict[str, int] = {}
            for match in pattern.finditer(text):
                first_seen.setdefault(match.group(1), match.start())
            if service == "bedrock":
                first_seen = {n: o for n, o in first_seen.items() if _BEDROCK_MODEL_RE.fullmatch(n)}
            # With several resources in one file the calls cannot be attributed to one of them.
            confident = intents if len(first_seen) == 1 else ()
            for name, offset in sorted(first_seen.items()):
                requirement = _requirement(
                    service, name, relative_path, line_at(text, offset),
                    f"AWS SDK call in {relative_path}", Confidence.MEDIUM, confident,
                )  # fmt: skip
                if not confident and intents:
                    requirement = requirement.model_copy(update={"intents": intents})
                result.requirements.append(requirement)
        return result


for _detector in (
    ArnDetector(),
    EnvDetector(),
    CloudFormationDetector(),
    ServerlessDetector(),
    TerraformDetector(),
    DockerDetector(),
    SdkDetector(),
):
    register(_detector)
