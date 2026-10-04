import boto3

s3 = boto3.client("s3")
runtime = boto3.client("bedrock-runtime")


def retrieve(key):
    return s3.get_object(Bucket="agent-knowledge-base", Key=key)


def listing():
    return s3.list_objects_v2(Bucket="agent-knowledge-base", Prefix="docs/")


def think(messages):
    return runtime.converse(
        modelId="us.anthropic.claude-3-5-sonnet-20241022-v2:0", messages=messages
    )
