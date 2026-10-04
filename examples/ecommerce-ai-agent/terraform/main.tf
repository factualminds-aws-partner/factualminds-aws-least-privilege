provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "assets" {
  bucket = "ecommerce-assets"
}

resource "aws_s3_bucket" "reports" {
  bucket = "ecommerce-reports"
}

# Not declared in fmaws.yaml: fmaws reports it as unconfirmed access.
resource "aws_s3_bucket" "traces" {
  bucket = "ecommerce-agent-traces"
}

resource "aws_dynamodb_table" "customers" {
  name         = "customers"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "customer_id"

  attribute {
    name = "customer_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "orders" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "order_id"

  attribute {
    name = "order_id"
    type = "S"
  }
}

resource "aws_sqs_queue" "order_processing" {
  name = "order-processing"
}

resource "aws_sns_topic" "order_events" {
  name = "order-events"
}

resource "aws_secretsmanager_secret" "api" {
  name = "prod/ecommerce/api"
}

resource "aws_cloudwatch_log_group" "agent" {
  name              = "/ecommerce/agent"
  retention_in_days = 30
}
