"""Declarative service definitions that drive generic policy generation.

Adding a service means adding one ``ServiceDefinition`` and registering it. S3 is not here:
its prefix semantics need a dedicated engine (``fmaws.policy.s3``).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from fmaws.errors import ConfigError

IAM_DOCS = "https://docs.aws.amazon.com/service-authorization/latest/reference"


@dataclass(frozen=True)
class ServiceDefinition:
    service: str
    title: str
    # Key naming the resource in fmaws.yaml (``table: customers``). ``<key>s`` accepts a list.
    config_key: str
    arn_template: str
    # Intent (the ``actions`` values in fmaws.yaml) -> explicit IAM actions.
    intents: Mapping[str, tuple[str, ...]]
    # Intents assumed when a resource is discovered but its usage is unknown.
    default_intents: tuple[str, ...]
    destructive_intents: frozenset[str] = frozenset()
    # Actions that do not support resource-level permissions -> why ``Resource: "*"`` is required.
    star_actions: Mapping[str, str] = field(default_factory=dict)
    # Intent -> suffixes appended to the base ARN as additional resources.
    extra_resources: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # Companion KMS permissions when the resource uses a customer managed key (``kms_key``).
    kms_actions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    kms_via_service: str = ""
    doc_url: str = ""

    def actions_for(self, intent: str) -> tuple[str, ...]:
        if intent not in self.intents:
            valid = ", ".join(sorted(self.intents))
            raise ConfigError(
                f"Unknown action '{intent}' for {self.service}. Supported actions: {valid}."
            )
        return self.intents[intent]


CATALOG: dict[str, ServiceDefinition] = {}


def register(definition: ServiceDefinition) -> None:
    CATALOG[definition.service] = definition


def get(service: str) -> ServiceDefinition:
    if service not in CATALOG:
        valid = ", ".join(["s3", *sorted(CATALOG)])
        raise ConfigError(f"Unsupported service '{service}'. Supported services: {valid}.")
    return CATALOG[service]


def star_actions() -> dict[str, str]:
    """All known actions that AWS only authorizes against ``Resource: "*"``."""
    known = {
        "s3:ListAllMyBuckets": "Listing buckets is an account-level operation.",
        "sts:GetCallerIdentity": "The operation is not tied to a resource.",
    }
    for definition in CATALOG.values():
        known.update(definition.star_actions)
    return known


def scoped_actions() -> set[str]:
    """All known actions that support resource-level permissions."""
    from fmaws.policy import s3  # s3 imports arns, which imports this module

    known = set(s3.ACTIONS)
    for definition in CATALOG.values():
        for actions in definition.intents.values():
            known.update(a for a in actions if a not in definition.star_actions)
        for actions in definition.kms_actions.values():
            known.update(actions)
    return known


_NOT_RESOURCE_LEVEL = "AWS does not support resource-level permissions for this list operation."

register(
    ServiceDefinition(
        service="dynamodb",
        title="DynamoDB table",
        config_key="table",
        arn_template="arn:{partition}:dynamodb:{region}:{account}:table/{name}",
        intents={
            "read": (
                "dynamodb:GetItem",
                "dynamodb:BatchGetItem",
                "dynamodb:Query",
                "dynamodb:Scan",
            ),
            "write": ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:BatchWriteItem"),
            "delete": ("dynamodb:DeleteItem",),
            "list": ("dynamodb:ListTables",),
        },
        default_intents=("read",),
        destructive_intents=frozenset({"delete"}),
        star_actions={"dynamodb:ListTables": _NOT_RESOURCE_LEVEL},
        # Query and Scan against secondary indexes are authorized on the index ARN.
        extra_resources={"read": ("/index/*",)},
        doc_url=f"{IAM_DOCS}/list_amazondynamodb.html",
    )
)

register(
    ServiceDefinition(
        service="sqs",
        title="SQS queue",
        config_key="queue",
        arn_template="arn:{partition}:sqs:{region}:{account}:{name}",
        intents={
            "send": ("sqs:SendMessage",),
            "receive": ("sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"),
            "read": ("sqs:GetQueueAttributes", "sqs:GetQueueUrl"),
            "purge": ("sqs:PurgeQueue",),
            "list": ("sqs:ListQueues",),
        },
        default_intents=("read",),
        destructive_intents=frozenset({"purge"}),
        star_actions={"sqs:ListQueues": _NOT_RESOURCE_LEVEL},
        kms_actions={
            "send": ("kms:GenerateDataKey", "kms:Decrypt"),
            "receive": ("kms:Decrypt",),
        },
        kms_via_service="sqs",
        doc_url=f"{IAM_DOCS}/list_amazonsqs.html",
    )
)

register(
    ServiceDefinition(
        service="sns",
        title="SNS topic",
        config_key="topic",
        arn_template="arn:{partition}:sns:{region}:{account}:{name}",
        intents={
            "publish": ("sns:Publish",),
            "subscribe": ("sns:Subscribe",),
            "list": ("sns:ListTopics",),
        },
        default_intents=("publish",),
        star_actions={"sns:ListTopics": _NOT_RESOURCE_LEVEL},
        kms_actions={"publish": ("kms:GenerateDataKey", "kms:Decrypt")},
        kms_via_service="sns",
        doc_url=f"{IAM_DOCS}/list_amazonsns.html",
    )
)

register(
    ServiceDefinition(
        service="secretsmanager",
        title="Secrets Manager secret",
        config_key="secret",
        # Secrets Manager appends a hyphen and six random characters to the secret name.
        arn_template="arn:{partition}:secretsmanager:{region}:{account}:secret:{name}-??????",
        intents={
            "read": ("secretsmanager:GetSecretValue",),
            "write": ("secretsmanager:PutSecretValue",),
            "delete": ("secretsmanager:DeleteSecret",),
            "list": ("secretsmanager:ListSecrets",),
        },
        default_intents=("read",),
        destructive_intents=frozenset({"delete"}),
        star_actions={"secretsmanager:ListSecrets": _NOT_RESOURCE_LEVEL},
        kms_actions={
            "read": ("kms:Decrypt",),
            "write": ("kms:GenerateDataKey", "kms:Decrypt"),
        },
        kms_via_service="secretsmanager",
        doc_url=f"{IAM_DOCS}/list_awssecretsmanager.html",
    )
)

register(
    ServiceDefinition(
        service="kms",
        title="KMS key",
        config_key="key",
        arn_template="arn:{partition}:kms:{region}:{account}:key/{name}",
        intents={
            "decrypt": ("kms:Decrypt",),
            "encrypt": ("kms:Encrypt", "kms:GenerateDataKey"),
            "read": ("kms:Decrypt",),
            "write": ("kms:Encrypt", "kms:GenerateDataKey"),
            "list": ("kms:ListAliases",),
        },
        default_intents=("decrypt",),
        star_actions={"kms:ListAliases": _NOT_RESOURCE_LEVEL},
        doc_url=f"{IAM_DOCS}/list_awskeymanagementservice.html",
    )
)

register(
    ServiceDefinition(
        service="lambda",
        title="Lambda function",
        config_key="function",
        arn_template="arn:{partition}:lambda:{region}:{account}:function:{name}",
        intents={
            "invoke": ("lambda:InvokeFunction",),
            "list": ("lambda:ListFunctions",),
        },
        default_intents=("invoke",),
        star_actions={"lambda:ListFunctions": _NOT_RESOURCE_LEVEL},
        doc_url=f"{IAM_DOCS}/list_awslambda.html",
    )
)

register(
    ServiceDefinition(
        service="eventbridge",
        title="EventBridge event bus",
        config_key="bus",
        arn_template="arn:{partition}:events:{region}:{account}:event-bus/{name}",
        intents={"publish": ("events:PutEvents",)},
        default_intents=("publish",),
        doc_url=f"{IAM_DOCS}/list_amazoneventbridge.html",
    )
)

register(
    ServiceDefinition(
        service="logs",
        title="CloudWatch Logs log group",
        config_key="log_group",
        arn_template="arn:{partition}:logs:{region}:{account}:log-group:{name}:*",
        intents={
            "write": ("logs:CreateLogStream", "logs:PutLogEvents"),
            "read": ("logs:GetLogEvents", "logs:FilterLogEvents"),
        },
        default_intents=("write",),
        doc_url=f"{IAM_DOCS}/list_amazoncloudwatchlogs.html",
    )
)

register(
    ServiceDefinition(
        service="ses",
        title="SES identity",
        config_key="identity",
        arn_template="arn:{partition}:ses:{region}:{account}:identity/{name}",
        intents={"send": ("ses:SendEmail", "ses:SendRawEmail")},
        default_intents=("send",),
        doc_url=f"{IAM_DOCS}/list_amazonses.html",
    )
)

register(
    ServiceDefinition(
        service="bedrock",
        title="Bedrock model",
        config_key="model",
        # Foundation models are AWS-owned: the ARN has no account ID.
        arn_template="arn:{partition}:bedrock:{region}::foundation-model/{name}",
        intents={
            "invoke": ("bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"),
            "list": ("bedrock:ListFoundationModels",),
        },
        default_intents=("invoke",),
        star_actions={"bedrock:ListFoundationModels": _NOT_RESOURCE_LEVEL},
        doc_url=f"{IAM_DOCS}/list_amazonbedrock.html",
    )
)

register(
    ServiceDefinition(
        service="rds",
        title="RDS IAM database user",
        config_key="db_user",
        # name is "<DbiResourceId>/<database user>", for example "db-ABCDEFGHIJKL/app".
        arn_template="arn:{partition}:rds-db:{region}:{account}:dbuser:{name}",
        intents={"connect": ("rds-db:connect",)},
        default_intents=("connect",),
        doc_url=f"{IAM_DOCS}/list_amazonrdsiamauthentication.html",
    )
)

register(
    ServiceDefinition(
        service="rds_data",
        title="Aurora cluster (RDS Data API)",
        config_key="cluster",
        arn_template="arn:{partition}:rds:{region}:{account}:cluster:{name}",
        intents={
            "execute": ("rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement"),
            "transaction": (
                "rds-data:BeginTransaction",
                "rds-data:CommitTransaction",
                "rds-data:RollbackTransaction",
            ),
        },
        default_intents=("execute",),
        doc_url=f"{IAM_DOCS}/list_amazonrdsdataapi.html",
    )
)
