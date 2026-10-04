# CI/CD

fmaws is built for pipelines: deterministic output, machine-readable formats and exit codes
that mean one thing each.

| Code | Meaning |
|---|---|
| 0 | Success, no threshold violation |
| 1 | Findings at or above the threshold |
| 2 | Configuration or runtime error, or an incomplete audit behind a threshold |
| 3 | AWS authentication or authorization error |

## Check the policy on every pull request (no AWS access)

```bash
fmaws generate --strict --output policy.json
git diff --exit-code policy.json      # the committed policy matches the project
fmaws validate policy.json --local-only
```

`generate` is deterministic, so committing `policy.json` and diffing it in CI turns every
permission change into a reviewable diff. `--strict` only includes resources declared in
`fmaws.yaml` and fails on warnings.

## Validate with IAM Access Analyzer

```bash
fmaws validate policy.json            # needs access-analyzer:ValidatePolicy
```

## Gate deployments on the account audit

```bash
fmaws audit --all-regions --fail-on high
```

If the CI role lacks a permission, the affected analyzer is skipped and, because a threshold is
set, the command exits 2 rather than passing. Attach `permissions/audit-readonly-policy.json`
to the CI role, or add `--allow-partial` if a partial audit is acceptable.

Thresholds can live in `fmaws.yaml` instead of the command line:

```yaml
audit:
  production:
    fail_on: [critical, high]
  non_production:
    fail_on: [critical]
```

## GitHub Actions

Use OpenID Connect so the workflow needs no stored AWS keys. The role's trust policy must pin
the `sub` claim to your repository; `fmaws audit` reports roles that do not
(`IAM_ROLE_TRUST_OIDC_UNRESTRICTED`).

```yaml
name: aws-security
on:
  pull_request:
  schedule:
    - cron: "0 3 * * 1"

permissions:
  id-token: write
  contents: read
  security-events: write

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv tool install .          # or: pipx install factualminds-aws-least-privilege
      - run: fmaws generate --strict --output policy.json
      - run: git diff --exit-code policy.json
      - run: fmaws validate policy.json --local-only

  audit:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv tool install .
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/fmaws-audit
          aws-region: ap-south-1
      - run: fmaws audit --all-regions --format sarif > fmaws.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: fmaws.sarif
      - run: fmaws audit --all-regions --fail-on high
```

## SARIF

`--format sarif` is available on `audit`, `validate` and `generate`. Findings map to SARIF
levels as CRITICAL and HIGH to `error`, MEDIUM to `warning`, LOW and INFO to `note`, with a
`security-severity` property so GitHub shows critical/high/medium/low.

An audit in which an analyzer could not run sets `executionSuccessful` to `false` in the SARIF
run and lists each affected analyzer as a tool notification, so an incomplete audit does not
look like a clean one.

AWS resources are not files, and code scanning requires a file location. Results therefore
point at the validated policy file, or at `fmaws.yaml` for an audit, and carry the AWS resource
as a logical location and in the message.

## Markdown for pull requests and reviews

```bash
fmaws audit --format markdown > aws-security-report.md
fmaws generate --format markdown > policy-report.md
```

## JSON

```bash
fmaws audit --format json | jq '.findings[] | select(.severity == "CRITICAL") | .resource'
fmaws audit --format json | jq .scores
```
