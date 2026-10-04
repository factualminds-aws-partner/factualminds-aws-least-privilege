# fmaws generate and fmaws explain

## generate

```bash
fmaws generate [--config PATH] [--output PATH] [--format console|json|markdown]
               [--profile NAME] [--region REGION] [--all-regions]
               [--strict] [--explain] [--validate]
```

Generates a candidate IAM policy for the project in the current directory.

- The policy is written to `--output` (default `generated-policy.json`). It is always plain,
  valid IAM JSON with no comments or metadata.
- The report is printed in `--format`. Explanations live in the report, never in the policy.
- The policy is never attached to anything.

| Option | Effect |
|---|---|
| `--config` | Use this file instead of `./fmaws.yaml` |
| `--output` | Where to write the policy |
| `--format` | `console` (default), `json`, `markdown` |
| `--profile` | AWS profile. Also makes fmaws resolve the account ID with `sts:GetCallerIdentity` |
| `--region` | Region written into ARNs |
| `--all-regions` | Write `*` in the region field of ARNs on purpose |
| `--strict` | Only resources declared in `fmaws.yaml`; warnings fail the run (exit 1) |
| `--explain` | Print reason, source and confidence for every statement |
| `--validate` | Also validate with IAM Access Analyzer (needs credentials) |

### Where account and region come from

1. `fmaws.yaml` (`aws.account_id`, `aws.region`) and `--region`
2. Discovery: a single account or region seen in ARNs, queue URLs, `AWS_REGION`, a Terraform
   provider block or a Serverless provider
3. The ambient AWS configuration for the region; `sts:GetCallerIdentity` for the account, only
   when `--profile` or `--validate` is given

`generate` makes no AWS call unless `--profile` or `--validate` is used, so it works offline
and its output does not depend on whichever credentials happen to be active.

If the account is still unknown, ARNs carry `*` in the account field and local validation
reports it. If the region is unknown, ARNs carry `*` and a note is printed.

### How discovered resources are treated

| Evidence | Confidence | Actions |
|---|---|---|
| Declared in `fmaws.yaml` | HIGH | Exactly what you declared |
| AWS SDK call with a literal resource name | MEDIUM | Inferred from the calls in that file |
| Literal ARN, SQS URL or resource name in config/env | MEDIUM | Service default, listed as unconfirmed |
| Resource defined in IaC | LOW | Service default, listed as unconfirmed |

"Unconfirmed" means the resource exists in your project but fmaws assumed what the application
does with it. Declare it in `fmaws.yaml` to settle the question. A resource that is declared is
never widened or narrowed by discovery.

Names that cannot be resolved statically (Terraform variables, CloudFormation intrinsics,
generated names) are counted in a note and left out of the policy.

### Policy minimization

The optimizer removes duplicate actions, merges statements with identical resources and
conditions, merges statements with identical actions and conditions, drops resources already
covered by a broader resource in the same statement, and drops actions already granted on the
same resources by another unconditional statement. It never merges statements with different
conditions, never merges across services, and never turns explicit actions into wildcards.

### Example report

```text
Generated policy: generated-policy.json
Account: ********3333  Region: ap-south-1

Local validation: PASS
AWS IAM Access Analyzer: PASS

Findings:
0 errors
0 warnings
0 recommendations

Unconfirmed access (resource detected, usage assumed):
  s3 ecommerce-agent-traces: assumed read (terraform/main.tf:15)
```

## explain

```bash
fmaws explain                # the policy generate would produce (writes nothing)
fmaws explain policy.json    # an existing policy
```

For the generated policy, each statement is listed with its reason, source and confidence:

```text
s3:GetObject, s3:PutObject
  Resource: arn:aws:s3:::ecommerce-assets/product-images/*
  Resource: arn:aws:s3:::ecommerce-assets/uploads/*
  Reason:
    Declared in configuration: list, read, write on s3://ecommerce-assets/product-images/*
  Source: fmaws.yaml:11
  Confidence: HIGH
```

For an existing file, each action is described from the service catalog (what kind of access it
is, or why it requires `Resource: "*"`), followed by the local validation findings. Actions
outside the catalog are labelled as such.
