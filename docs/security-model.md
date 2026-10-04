# Security model

## Read only

fmaws never changes an AWS account. There is no remediation, no policy attachment and no
mutating API call in the code base. The only AWS operations it calls are:

| Operation | Used by |
|---|---|
| `sts:GetCallerIdentity` | `doctor`; `generate` with `--profile` or `--validate` |
| `access-analyzer:ValidatePolicy` | `validate`; `generate --validate`; `doctor` |

`fmaws audit` additionally calls the read-only operations listed in
[required-aws-permissions.md](required-aws-permissions.md). Every audit call passes through an
allow-list (`OPERATIONS` in `fmaws/audit/base.py`); an operation that is not on the list raises
an error instead of being sent. The only non-`Get`/`List`/`Describe` entry is
`iam:GenerateCredentialReport`, which refreshes a report and changes no resource.

`fmaws observe` calls four operations, also behind an allow-list (`OPERATIONS` in
`fmaws/observe.py`): `iam:GenerateServiceLastAccessedDetails`,
`iam:GetServiceLastAccessedDetails`, `cloudtrail:LookupEvents` and
`access-analyzer:GetGeneratedPolicy`. It never starts an Access Analyzer policy generation job.

Tests assert that no other operation or service client appears in the source. Any future
capability that changes an account must be a separate, explicit command with confirmation.
The audit never reads secret values, S3 objects or key material: it reads configuration and
policies only.

## Credentials

fmaws uses the standard AWS credential provider chain through boto3: profiles, environment
variables, IAM Identity Center (SSO), instance, task and Lambda roles, and role assumption
configured in `~/.aws/config`. It stores no credentials and prints none. `doctor` shows the
account ID masked to its last four digits.

## Static analysis only

- Project files are parsed, never executed. No application code, Terraform, CDK or shell runs.
- YAML is loaded with PyYAML's safe loader. CloudFormation short-form tags (`!Ref`, `!Sub`)
  become inert values. Python object tags are rejected.
- Terraform is parsed as HCL. Expressions, functions, variables and data sources are not
  evaluated; names that depend on them are reported as unresolved.
- A file that cannot be parsed is skipped with a note. It does not abort the run.

## File access

- The walker stays inside the project directory, does not follow directory symlinks, and skips
  file symlinks that resolve outside the project.
- `discovery.paths` entries that point outside the project are a configuration error.
- Files larger than 2 MB and more than 5,000 files are not read.
- Source code is never uploaded. The only data sent to AWS is the policy document passed to
  Access Analyzer when you ask for it.

## Secrets

- Environment-style values are kept only when the key and the value look like an AWS resource
  reference (a bucket name under a `*BUCKET*` key, and so on). Every other value is discarded
  while parsing and never stored in memory structures, reports or the policy.
- All output passes through a redaction filter that removes access key IDs and
  `password=`/`secret_key=`-style assignments, as a second line of defense.
- Tests plant credentials in fixture projects and assert that they do not appear in any output
  format or in the generated policy.

## Input that becomes policy

Resource names are data, not patterns. Names with `*`, `?`, whitespace, quotes or newlines are
rejected, so a name can neither widen a statement nor inject JSON. The policy is serialized
with a JSON encoder, never by string concatenation.

## Generated policies

- No wildcard actions are generated.
- `Resource: "*"` is generated only for actions that AWS does not authorize at resource level,
  each in its own explained statement.
- Golden tests fail on any change to the policies generated for the fixture projects.
