"""Order-support agent: answers customer questions about orders using Amazon Bedrock."""

import json
import os

import boto3

MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"

s3 = boto3.client("s3")
dynamodb = boto3.client("dynamodb")
sqs = boto3.client("sqs")
secrets = boto3.client("secretsmanager")
bedrock = boto3.client("bedrock-runtime")


def load_customer(customer_id: str) -> dict:
    response = dynamodb.get_item(TableName="customers", Key={"customer_id": {"S": customer_id}})
    return response.get("Item", {})


def product_image(key: str) -> bytes:
    return s3.get_object(Bucket="ecommerce-assets", Key=f"product-images/{key}")["Body"].read()


def answer(question: str, customer_id: str) -> str:
    customer = load_customer(customer_id)
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "messages": [{"role": "user", "content": f"{question}\n\nCustomer: {customer}"}],
        }
    )
    response = bedrock.invoke_model(modelId=MODEL_ID, body=body)
    return json.loads(response["body"].read())["content"][0]["text"]


def enqueue_follow_up(order_id: str) -> None:
    sqs.send_message(QueueUrl=os.environ["ORDER_QUEUE_URL"], MessageBody=order_id)
