# fmaws validate

```bash
fmaws validate policy.json                 # local checks, then IAM Access Analyzer
fmaws validate policy.json --local-only    # no AWS calls
fmaws validate policy.json --format json
fmaws generate --validate                  # validate what was just generated
```

Local validation always runs first and its result is printed even if the AWS call then fails.

```text
Policy: policy.json

Local validation: PASS
AWS IAM Access Analyzer: PASS

Findings:
0 errors
1 warning
2 recommendations
```

Errors are CRITICAL and HIGH findings, warnings are MEDIUM, recommendations are LOW and INFO.
The command exits 1 when there is at least one error.

## Local checks

| Finding | Severity | Meaning |
|---|---|---|
| `POLICY_INVALID_JSON` | HIGH | Not JSON, duplicate keys, `NaN`/`Infinity` |
| `POLICY_TOO_LARGE` | HIGH | File larger than 1 MB |
| `POLICY_INVALID_STRUCTURE` | HIGH | Grammar problems, unknown or misspelled elements, empty `Statement` |
| `POLICY_INVALID_ACTION` | HIGH | Not of the form `service:Action` |
| `POLICY_INVALID_ARN` | HIGH | Resource is neither `*` nor an ARN |
| `POLICY_DUPLICATE_SID` | HIGH | `Sid` repeated |
| `POLICY_FULL_ADMIN` | CRITICAL | Every action on every resource, in any spelling (`*`, `*:*`, `arn:aws:*:*:*:*`) |
| `POLICY_ACTION_WILDCARD` | HIGH | Every action on specific resources or under a condition |
| `POLICY_SERVICE_WILDCARD` | configurable; HIGH for `iam`, `sts`, `kms`, `organizations` and whenever the resource is `*` | `service:*` |
| `POLICY_PARTIAL_WILDCARD` | LOW; MEDIUM on `Resource: "*"`; HIGH for `iam`, `sts`, `kms`, `organizations` | `s3:Get*` |
| `POLICY_NOT_ACTION_ALLOW` | HIGH | `Allow` with `NotAction` |
| `POLICY_NOT_RESOURCE_ALLOW` | MEDIUM | `Allow` with `NotResource`. The statement is then checked as if it applied to every resource |
| `POLICY_PASSROLE_BROAD` | HIGH | `iam:PassRole` on every role without a restricting `iam:PassedToService` |
| `POLICY_PRIVILEGE_ESCALATION` | HIGH; MEDIUM when conditioned | `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:CreateAccessKey`, `sts:AssumeRole` and similar on arbitrary users, roles, groups or policies |
| `POLICY_RESOURCE_WILDCARD` | MEDIUM | Actions that support resource-level permissions on `Resource: "*"` |
| `POLICY_RESOURCE_WILDCARD_UNKNOWN` | LOW | `Resource: "*"` on actions outside the fmaws catalog |
| `POLICY_BROAD_RESOURCE` | MEDIUM; HIGH for a wildcard service; LOW when conditioned | Every resource of a service or of a type (`table/*`). `key/*` pinned with `kms:ResourceAliases` is accepted |
| `POLICY_ACCOUNT_WILDCARD` | LOW | ARN without a pinned account |
| `POLICY_PUBLIC_PRINCIPAL` | CRITICAL; MEDIUM when conditioned; HIGH for `NotPrincipal` | Wildcard principal |
| `POLICY_VERSION` | MEDIUM | `Version` is not `2012-10-17` |
| `POLICY_SIZE` | MEDIUM | Larger than the 6,144 character managed policy limit |

Design choices that keep false positives low and prevent silent passes:

- Not every wildcard is critical. `dynamodb:ListTables` on `Resource: "*"` is not reported at
  all because AWS offers no narrower form.
- Action names are compared case-insensitively, as IAM does. `iam:passrole` and `iam:Pass*` are
  recognized as `iam:PassRole`.
- A condition never removes a finding unless fmaws can tell that it restricts
  (`iam:PassedToService` with specific services, `kms:ResourceAliases` with specific aliases).
  Any other condition lowers the severity at most, and a condition that is always true
  (`StringLike` with `*`) does not even do that.
- An invalid element is reported and the rest of the statement is still checked.
- `Deny` statements are not checked for breadth.

Local validation is written for identity policies. It recognizes `Principal` so that resource
policies do not produce grammar errors, but it is not a resource policy analyzer.

## IAM Access Analyzer

fmaws calls `access-analyzer:ValidatePolicy` once per document with policy type
`IDENTITY_POLICY` and follows pagination. Every finding AWS returns is shown; none is filtered.

| Access Analyzer type | fmaws severity |
|---|---|
| `ERROR` | HIGH |
| `SECURITY_WARNING` | MEDIUM |
| `WARNING` | MEDIUM |
| `SUGGESTION` | LOW |

If no region is configured, `us-east-1` is used for this call. Without credentials or without
the permission, the command exits 3 after printing the local result; use `--local-only`.

Reference: [IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html),
[policy check reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html).
