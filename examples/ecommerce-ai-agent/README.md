# Example: ecommerce AI agent

An order-support agent for an online shop. It reads customer and order data from DynamoDB,
product images from S3, an API key from Secrets Manager, answers questions with Amazon Bedrock,
queues follow-ups in SQS, publishes order events to SNS and writes logs to CloudWatch Logs.

```
fmaws.yaml         what the application needs, declared (HIGH confidence)
terraform/main.tf  the infrastructure, including one bucket that is not declared
src/agent.py       the application code
.env.example       environment configuration
```

## Generate

```bash
cd examples/ecommerce-ai-agent
fmaws generate
fmaws generate --explain
```

Things to notice in the result:

- `s3:ListBucket` on `ecommerce-assets` is limited to `uploads/*` and `product-images/*` with
  the `s3:prefix` condition; object access is limited to the same two folders.
- `ecommerce-reports` is read-only and limited to `reports/`.
- The SSE-KMS key gets `kms:Decrypt` and `kms:GenerateDataKey`, only through S3
  (`kms:ViaService`).
- The Bedrock statement names one model. There is no `bedrock:*`.
- `ecommerce-agent-traces` is defined in Terraform but not declared in `fmaws.yaml`. fmaws
  includes read access at LOW confidence and lists it under "Unconfirmed access". Either declare
  it with the folders and actions the agent uses, or run `fmaws generate --strict` to leave
  undeclared resources out.

## Validate

```bash
fmaws validate generated-policy.json --local-only    # offline
fmaws validate generated-policy.json                 # adds IAM Access Analyzer
```

## Audit the account the application runs in

```bash
fmaws audit --region ap-south-1
fmaws audit --region ap-south-1 --fail-on high --format markdown > aws-security-report.md
```

The audit looks at the account, not at this directory: public buckets, security groups open on
database ports, IAM policies that can read every secret, and so on. See
[docs/audit.md](../../docs/audit.md).

## Observe what the agent's role really uses

```bash
fmaws observe --principal role/ecommerce-agent --days 90
fmaws observe --principal role/ecommerce-agent --days 120 --output recommended-policy.json
```

Each permission of the generated policy is reported as used, unused, unknown or potentially
missing. Everything declared in `fmaws.yaml` stays in the recommended policy whatever the
evidence says; see [docs/observe.md](../../docs/observe.md).
