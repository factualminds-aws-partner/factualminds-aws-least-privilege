# FactualMinds AWS Least Privilege Advisor

[![CI](https://github.com/factualminds-aws-partner/factualminds-aws-least-privilege/actions/workflows/ci.yml/badge.svg)](https://github.com/factualminds-aws-partner/factualminds-aws-least-privilege/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2a6db2.svg)](https://mypy-lang.org/)
[![AWS: read-only](https://img.shields.io/badge/AWS-read--only-orange.svg)](docs/security-model.md)

`fmaws` is a developer CLI that helps teams reduce AWS permissions to the smallest practical
set and find the account security problems worth fixing first.

It answers practical questions:

- What AWS permissions does my application actually need, and **why** does each one exist?
- Which S3 buckets and folders does it really use?
- Which permissions are broader than they need to be?
- Which of the permissions I granted are used, unused or simply unknown?
- What is publicly exposed or over-privileged in this account right now?

It is **framework-agnostic** (no Laravel, Node.js, Django or any other framework is assumed),
**read-only** (it never attaches a policy, never changes an AWS account, never remediates) and
it never uploads your code anywhere.

> **Maturity: alpha.** The test suite runs entirely against stubbed and simulated AWS
> responses. Run it against a non-production account first and review what it reports. A
> generated policy is a candidate, not a proof: see [limitations](docs/limitations.md).

## Contents

- [Key features](#key-features)
- [Quick start](#quick-start)
- [Installation](#installation)
- [Commands](#commands)
- [Example: a least-privilege S3 policy](#example-a-least-privilege-s3-policy)
- [Configuration](#configuration)
- [What it supports](#what-it-supports)
- [CI/CD](#cicd)
- [AWS permissions the tool needs](#aws-permissions-the-tool-needs)
- [Security model](#security-model)
- [Architecture](#architecture)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Key features

- **Policy generation with explanations.** Every statement carries a reason, a source
  (`fmaws.yaml:12`) and a confidence level. No wildcard actions are ever generated.
- **S3 done properly.** Folder-level access with `s3:ListBucket` on the bucket and an
  `s3:prefix` condition, object actions on object ARNs, multipart, versioning, SSE-KMS and
  cross-account buckets. A folder is never widened to the bucket.
- **Zero-config discovery.** Finds resources in `.env` files, CloudFormation, SAM, synthesized
  CDK, Terraform, Serverless Framework, docker-compose, literal ARNs and AWS SDK calls. Static
  analysis only: nothing is executed.
- **Policy validation.** Offline checks plus IAM Access Analyzer. Catches full admin in every
  spelling, broad `iam:PassRole`, privilege escalation, service wildcards, typos IAM would
  reject.
- **Account audit.** Ten analyzers (root user, credentials, IAM policies, role trust, S3,
  security groups, CloudTrail, Secrets Manager, KMS, RDS) with a documented score and
  severities based on exposure and privilege, not on wildcard counting.
- **Observed access.** Compares a policy with what a role actually did: used, unused, unknown,
  potentially missing. "Unused" is never silently treated as "unnecessary".
- **CI-friendly.** Deterministic output, JSON / Markdown / SARIF, `--fail-on`, and exit codes
  that each mean one thing.

## Quick start

```bash
cd my-project

fmaws doctor                                   # check AWS credentials (optional)
fmaws generate                                 # writes generated-policy.json
fmaws generate --explain                       # why each statement exists
fmaws validate generated-policy.json           # offline checks + IAM Access Analyzer
fmaws audit --region ap-south-1                # read-only account audit
fmaws observe --principal role/my-app          # what the role really uses
```

`generate`, `explain` and `validate --local-only` make **no AWS calls** and need no credentials.

## Installation

Requires Python 3.12 or newer. The package is not on PyPI yet; install from a clone:

```bash
git clone https://github.com/factualminds-aws-partner/factualminds-aws-least-privilege.git
cd factualminds-aws-least-privilege

pipx install .            # or: uv tool install .
fmaws --version
python -m fmaws --help    # also works as a module
```

AWS credentials are taken from the standard provider chain (profiles, environment variables,
IAM Identity Center/SSO, instance, task and Lambda roles). fmaws stores no credentials.

## Commands

| Command | What it does | AWS calls |
|---|---|---|
| `fmaws generate` | Candidate least-privilege policy for the project in the current directory | none (STS and Access Analyzer only with `--profile` / `--validate`) |
| `fmaws explain [FILE]` | Reason, source and confidence for every statement | none |
| `fmaws validate FILE` | Offline validation, then IAM Access Analyzer | `access-analyzer:ValidatePolicy` (none with `--local-only`) |
| `fmaws audit` | Read-only security audit of the account, with scores | read-only `Get`/`List`/`Describe` |
| `fmaws observe` | Used / unused / unknown / potentially missing permissions for one principal | IAM last accessed, optional CloudTrail lookup |
| `fmaws doctor` | Credentials, identity, region, connectivity | `sts:GetCallerIdentity` |

Common options: `--profile`, `--region`, `--config`, `--format console|json|markdown|sarif`.

```bash
fmaws generate --strict --output policy.json   # only declared resources; warnings fail
fmaws generate --all-regions                   # do not pin ARNs to one Region
fmaws validate policy.json --local-only
fmaws audit --all-regions --fail-on high
fmaws audit --format markdown > aws-security-report.md
fmaws observe --principal role/my-app --days 120 --output recommended-policy.json
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no threshold violation |
| 1 | Findings at or above the threshold (`validate`: errors; `generate --strict`: warnings; `audit --fail-on`) |
| 2 | Configuration or runtime error, or an incomplete audit behind `--fail-on` |
| 3 | AWS authentication or authorization error |

## Example: a least-privilege S3 policy

`fmaws.yaml`:

```yaml
aws:
  region: ap-south-1
  account_id: "111122223333"

resources:
  s3:
    - bucket: ecommerce-assets
      prefixes: [uploads/, product-images/]
      actions: [read, write, list]
  dynamodb:
    - table: customers
      actions: [read]
```

`fmaws generate` produces, among others:

```json
{
  "Sid": "S3ListBucket48cea8",
  "Effect": "Allow",
  "Action": "s3:ListBucket",
  "Resource": "arn:aws:s3:::ecommerce-assets",
  "Condition": {
    "StringLike": { "s3:prefix": ["product-images/*", "uploads/*"] }
  }
},
{
  "Sid": "S3GetObject44a7ed",
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": [
    "arn:aws:s3:::ecommerce-assets/product-images/*",
    "arn:aws:s3:::ecommerce-assets/uploads/*"
  ]
}
```

and `fmaws generate --explain` says why:

```text
s3:GetObject, s3:PutObject
  Resource: arn:aws:s3:::ecommerce-assets/product-images/*
  Resource: arn:aws:s3:::ecommerce-assets/uploads/*
  Reason:
    Declared in configuration: list, read, write on s3://ecommerce-assets/product-images/*
  Source: fmaws.yaml:11
  Confidence: HIGH
```

A complete project (configuration, Terraform, application code) is in
[`examples/ecommerce-ai-agent`](examples/ecommerce-ai-agent).

### An audit finding

```text
CRITICAL  S3
Bucket allows public write access
Resource: arn:aws:s3:::ecommerce-assets

Problem:
Anonymous users may upload or modify objects.

Fix:
Enable S3 Block Public Access and remove public-write bucket policy statements and ACL grants.

Confidence: HIGH
```

## Configuration

Configuration is optional. Without `fmaws.yaml`, resources are discovered from the project and
listed as *unconfirmed* when fmaws cannot tell what the application does with them. Declaring
them gives an exact, HIGH-confidence policy.

| Confidence | Source |
|---|---|
| HIGH | Declared in `fmaws.yaml` |
| MEDIUM | Literal ARN, queue URL or resource name in project files, or an AWS SDK call |
| LOW | Resource defined in infrastructure-as-code, usage unknown |

`fmaws.yaml` also holds audit thresholds, ignored findings, intentional public buckets, trusted
accounts and the principal to observe. User-level defaults go in
`~/.config/fmaws/config.yaml`. Full reference: [docs/configuration.md](docs/configuration.md).

## What it supports

**Policy generation:** S3 (dedicated prefix engine), DynamoDB, SQS, SNS, Secrets Manager, KMS,
Lambda, EventBridge, CloudWatch Logs, SES, Bedrock (foundation models and inference profiles),
RDS (IAM database authentication and the Data API).

**Project sources:** `fmaws.yaml`, `.env` files, CloudFormation, AWS SAM, synthesized CDK
templates, Terraform, Serverless Framework, docker-compose and Dockerfile `ENV`, literal ARNs
and SQS URLs in any text file, AWS SDK calls with literal resource names.

**Audit analyzers:** `iam_root`, `iam_credentials`, `iam_policies`, `iam_roles`, `s3`,
`network`, `cloudtrail`, `secrets`, `kms`, `rds`. See [docs/audit.md](docs/audit.md) for every
finding and the scoring model.

**Report formats:** console, JSON, Markdown, SARIF 2.1.0.

## CI/CD

```bash
# Pull requests, no AWS access needed
fmaws generate --strict --output policy.json
git diff --exit-code policy.json          # permission changes become a reviewable diff
fmaws validate policy.json --local-only

# Scheduled, with a read-only role
fmaws audit --all-regions --format sarif > fmaws.sarif
fmaws audit --all-regions --fail-on high
```

With `--fail-on`, an audit in which an analyzer could not run exits 2 instead of passing: a gate
should not pass because the tool could not look. A complete GitHub Actions workflow with OIDC
and SARIF upload is in [docs/ci-cd.md](docs/ci-cd.md).

## AWS permissions the tool needs

fmaws never needs `AdministratorAccess` or any write permission.

| Command | Permissions |
|---|---|
| `generate`, `explain`, `validate --local-only` | none |
| `validate` | `access-analyzer:ValidatePolicy` |
| `audit` | [`permissions/audit-readonly-policy.json`](permissions/audit-readonly-policy.json) (or the AWS managed `SecurityAudit` policy) |
| `observe` | [`permissions/observe-policy.json`](permissions/observe-policy.json) |

Details: [docs/required-aws-permissions.md](docs/required-aws-permissions.md).

## Security model

- **Read-only.** `audit` and `observe` can only call operations on an allow-list; anything
  else raises instead of being sent. The permission files above are generated from those lists.
- **Static analysis only.** Project files are parsed, never executed. YAML is loaded safely,
  Terraform is parsed and not evaluated.
- **No secrets in output.** Environment values are kept only when they look like AWS resource
  references; everything else is discarded while parsing, and all output is redacted as a
  second line of defense.
- **Names are data, not patterns.** Resource names with wildcards, whitespace or quotes are
  rejected, so input can neither widen a statement nor inject JSON.
- **Unknown is never reported as clean.** A denied API call or an unreadable policy marks the
  analyzer incomplete.

More in [docs/security-model.md](docs/security-model.md).

## Architecture

```
fmaws.yaml ──► config/loader ──┐
                               ├─► discovery/merge ─► policy/generator ─► policy/optimizer
project files ─► discovery ────┘                          │   │                 │
                                                      catalog  s3 engine        ▼
                                                                          PolicyDocument
                                                  validators/local  ◄───────────┤
                                         validators/access_analyzer ◄───────────┤
                                                                                ▼
            audit/ (analyzers) ─► findings ─► scoring ─────────────► Report ─► reporters
            observe  (evidence) ─► observations ───────────────────►
```

```
src/fmaws/
├── cli/          Typer commands and exit-code mapping
├── config/       fmaws.yaml schema and loading
├── discovery/    file walker, detectors, requirement merging
├── policy/       service catalog, S3 engine, ARN helpers, generator, optimizer
├── validators/   local validation, IAM Access Analyzer
├── audit/        allow-listed AWS access, analyzers, rule catalog, scoring
├── observe.py    last accessed, CloudTrail lookup, classification
├── aws/          session, cached clients, error translation
├── models/       requirement, policy, finding, report
├── reporters/    console, JSON, Markdown, SARIF
└── utils/        redaction, text helpers
```

New services, detectors, analyzers and report formats are registered, not wired into the CLI:
a new AWS service is one `ServiceDefinition`. See [docs/architecture.md](docs/architecture.md).

## Development

```bash
git clone https://github.com/factualminds-aws-partner/factualminds-aws-least-privilege.git
cd factualminds-aws-least-privilege
uv sync                       # creates .venv with runtime and dev dependencies

uv run fmaws --help
uv run pytest                 # full suite, offline, about two seconds
uv run ruff check .
uv run ruff format --check .
uv run mypy src               # strict
```

| Path | Contents |
|---|---|
| `tests/unit/` | Unit and CLI tests. No network: AWS is stubbed or simulated |
| `tests/fixtures/` | Five realistic projects (SaaS, AI agent, image pipeline, order pipeline, reporting) |
| `tests/golden/` | The exact policy expected for each fixture and for the example project |
| `examples/ecommerce-ai-agent/` | Runnable example |
| `permissions/` | IAM policies the tool itself needs, generated from the allow-lists |

After an intentional change to generation, refresh the golden policies and review the diff for
wildcard escalation:

```bash
UPDATE_GOLDEN=1 uv run pytest tests/unit/test_golden.py
git diff tests/golden
```

## Troubleshooting

**`No AWS resources were declared or detected`**
Nothing in the project names an AWS resource literally. Create `fmaws.yaml` and list the
resources ([docs/configuration.md](docs/configuration.md)).

**ARNs contain `*` as account or Region**
fmaws could not determine them offline. Set `aws.account_id` and `aws.region` in `fmaws.yaml`,
or pass `--region` and `--profile`.

**`resource name(s) use variables or expressions and were not resolved`**
Terraform variables and CloudFormation intrinsics are not evaluated. Declare those resources in
`fmaws.yaml` with their real names.

**Exit code 3: `No usable AWS credentials`**
Configure a profile (`aws configure sso`), set `AWS_PROFILE`, or pass `--profile`. For an
expired SSO session run `aws sso login`. `fmaws doctor` shows what was resolved.

**`validate` fails with exit 3 but the policy looks fine**
The local result is printed first; the failure is the Access Analyzer call. Grant
`access-analyzer:ValidatePolicy` or use `--local-only`.

**`audit` shows analyzers as skipped**
The role lacks a permission; the report names it. Attach
`permissions/audit-readonly-policy.json`. With `--fail-on` this exits 2 unless you pass
`--allow-partial`.

**`observe` reports most permissions as unknown**
Expected for data-plane actions such as `s3:GetObject`: IAM does not track them individually
and CloudTrail lookup only sees management events. See [docs/observe.md](docs/observe.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [generate and explain](docs/generate.md)
- [validate](docs/validate.md)
- [audit](docs/audit.md)
- [observe](docs/observe.md)
- [CI/CD](docs/ci-cd.md)
- [S3 least privilege](docs/s3-least-privilege.md)
- [Security model](docs/security-model.md)
- [Required AWS permissions](docs/required-aws-permissions.md)
- [Limitations](docs/limitations.md)

## Contributing

Issues and pull requests are welcome. Before opening a pull request, run the four checks under
[Development](#development); CI runs the same ones. Changes that alter generated policies must
update `tests/golden/` and explain the difference. Anything that would make the tool call a
non-read-only AWS operation is out of scope.

To report a security problem in fmaws itself, please use GitHub's private vulnerability
reporting on this repository rather than a public issue.

## License

[MIT](LICENSE)
