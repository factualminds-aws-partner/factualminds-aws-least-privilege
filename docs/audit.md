# fmaws audit

```bash
fmaws audit                         # the configured Region
fmaws audit --profile production --region ap-south-1
fmaws audit --all-regions
fmaws audit --format json | markdown | sarif
fmaws audit --fail-on high          # exit 1 on HIGH or CRITICAL findings
```

The audit is **read-only**. It never disables users, deletes or rotates credentials, changes
policies, security groups or bucket settings, or enables services. It reports problems and how
to fix them; you make the change.

It is a focused advisor, not a full CSPM: a small number of checks chosen for high signal,
ordered by how exposed and how privileged the affected resource is.

## Example report

```text
Account: ********3333  Region: ap-south-1

AWS Security Score: 40/100
Least Privilege Score: 100/100

Completed: 9 analyzers
Skipped: 1
Failed: 0
  rds: skipped, ap-south-1: missing permission rds:DescribeDBInstances

Findings:
2 critical
1 high
0 medium
0 low
0 info

CRITICAL  S3
Bucket allows public write access
Resource: arn:aws:s3:::ecommerce-assets

Problem:
Anonymous users may upload or modify objects.

Fix:
Enable S3 Block Public Access and remove public-write bucket policy statements and ACL grants.

Confidence: HIGH
```

Every finding carries: `id`, `severity`, `category`, `service`, `resource`, `title`, `problem`,
`why_it_matters`, `evidence`, `recommendation`, `remediation`, `documentation_url`,
`confidence` and `is_auto_fixable` (always `false`: fmaws fixes nothing).

## Regions

Global services (IAM, S3, CloudTrail coverage) are always audited. Regional analyzers
(`network`, `secrets`, `kms`, `rds`) run only in the selected Regions: `--region`, else
`audit.regions`, else `aws.region`, else the Region of the AWS profile. `--all-regions` audits
every Region enabled for the account and costs proportionally more API calls.

## Checks

Severities are defaults; several depend on context as noted.

### Root user (`iam_root`)

| Finding | Severity |
|---|---|
| `IAM_ROOT_MFA_DISABLED` | CRITICAL |
| `IAM_ROOT_ACCESS_KEYS` | CRITICAL |
| `IAM_ROOT_RECENT_USE` (used in the last 30 days) | MEDIUM |

Root is treated separately because IAM policies cannot restrict it. Never use root credentials
for applications: workloads should use roles and temporary credentials, people should use IAM
Identity Center.

### IAM credentials (`iam_credentials`)

| Finding | Severity |
|---|---|
| `IAM_USER_NO_MFA` (console password, no MFA) | HIGH |
| `IAM_ACCESS_KEY_OLD` (older than `max_access_key_age_days`) | MEDIUM |
| `IAM_ACCESS_KEY_UNUSED` (active, idle longer than `unused_days`) | MEDIUM |
| `IAM_USER_INACTIVE` | LOW |

### IAM permissions (`iam_policies`)

Customer managed policies (default version) and inline policies are checked with the same rules
as `fmaws validate`.

| Finding | Severity |
|---|---|
| `IAM_ADMIN_ATTACHED` | HIGH for users and groups, MEDIUM for roles; roles managed by IAM Identity Center are not reported |
| `IAM_POLICY_ADMIN` (`*` on `*`) | HIGH |
| `IAM_POLICY_ACTION_WILDCARD`, `IAM_POLICY_NOT_ACTION` | HIGH |
| `IAM_POLICY_PASSROLE` (any role, no `iam:PassedToService`) | HIGH |
| `IAM_POLICY_PRIVILEGE_ESCALATION` | HIGH |
| `IAM_POLICY_SERVICE_WILDCARD` | MEDIUM; HIGH for `iam:*`, `sts:*`, `kms:*` or on `Resource: "*"` |
| `IAM_POLICY_RESOURCE_WILDCARD` | MEDIUM |
| `IAM_SECRETS_WILDCARD_ACCESS` (can read every secret, in any or in one Region) | HIGH; MEDIUM when conditioned |
| `IAM_DYNAMODB_WILDCARD_ACCESS` (data access to every table) | MEDIUM; LOW when conditioned |
| `IAM_USER_INLINE_POLICY` | LOW |

A wildcard is not automatically critical. A customer managed policy that is **not attached** to
anything is reported at LOW whatever it contains, and `dynamodb:ListTables` on `*` is not
reported at all because AWS offers no narrower form.

### IAM roles (`iam_roles`)

| Finding | Severity |
|---|---|
| `IAM_ROLE_TRUST_PUBLIC` (`Principal: "*"`) | CRITICAL; MEDIUM when a condition applies that fmaws cannot verify. `sts:ExternalId` alone is such a condition: it is a shared secret, not an identity |
| `IAM_ROLE_TRUST_OIDC_UNRESTRICTED` (the `sub` claim is not pinned to an owner, for example `repo:*`) | HIGH |
| `IAM_ROLE_TRUST_CROSS_ACCOUNT` | MEDIUM; LOW with `sts:ExternalId` or an organization condition; not reported for `trusted_accounts` |
| `IAM_ROLE_UNUSED` (older and idle longer than `unused_days`) | LOW, confidence MEDIUM |

### S3 (`s3`)

| Finding | Severity |
|---|---|
| `S3_PUBLIC_WRITE`, `S3_PUBLIC_DELETE` | CRITICAL |
| `S3_PUBLIC_READ` | HIGH |
| `S3_PUBLIC_READ_INTENTIONAL` (listed in `intentional_public`) | INFO |
| `S3_PUBLIC_BLOCKED` (public grants overridden by Block Public Access) | LOW |
| `S3_WILDCARD_PRINCIPAL_CONDITIONED` | MEDIUM |
| `S3_CROSS_ACCOUNT_ACCESS` | MEDIUM when the other account can modify data, else LOW |
| `S3_ACCOUNT_BPA_DISABLED` | MEDIUM |
| `S3_ENCRYPTION_MISSING` | LOW |
| `S3_BUCKET_BPA_DISABLED`, `S3_ACLS_ENABLED`, `S3_VERSIONING_DISABLED` | LOW, one finding for all affected buckets |
| `S3_LOGGING_DISABLED` | INFO, one finding for all affected buckets |

Public exposure is computed from the bucket policy, the bucket ACL, object ownership and the
effective Block Public Access settings (account and bucket). Any action granted to a wildcard
principal (or through `NotPrincipal`) is reported, not only the common ones.

A wildcard principal is treated as not public only when a condition demonstrably pins the
caller: a specific value for `aws:SourceIp`, `aws:SourceVpce`, `aws:PrincipalOrgID`,
`aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalAccount` or `aws:PrincipalArn`. These do
**not** count: negated operators, `...IfExists` and `ForAllValues:` forms (true when the key
is absent), wildcard values whose ARN account field is not a specific account (`vpce-*`,
`arn:aws:iam::*:role/*`), IP ranges that together cover more than a /8 (IPv4) or /16 (IPv6),
and `kms:ViaService` on its own (it pins a service, not a caller). When the pinned account is another account, the
statement is reported as cross-account access. The same rules apply to KMS key policies and
role trust policies.

A policy that cannot be parsed unambiguously (invalid JSON, duplicate keys) is never read as
empty: the analyzer is marked incomplete.

### Network (`network`)

| Finding | Severity |
|---|---|
| `SG_OPEN_ALL_PORTS` from `0.0.0.0/0` or `::/0` | CRITICAL; MEDIUM if the group is not attached |
| `SG_OPEN_SENSITIVE_PORT` | HIGH; LOW if the group is not attached |

Sensitive ports: 22 SSH, 3389 RDP, 3306 MySQL, 5432 PostgreSQL, 6379 Redis, 1433 SQL Server,
1521 Oracle, 27017 MongoDB, 9200 Elasticsearch, 11211 Memcached. Public HTTP and HTTPS are not
reported.

### CloudTrail (`cloudtrail`)

| Finding | Severity |
|---|---|
| `CLOUDTRAIL_NO_TRAIL`, `CLOUDTRAIL_NOT_LOGGING` | HIGH |
| `CLOUDTRAIL_NOT_MULTI_REGION`, `CLOUDTRAIL_MANAGEMENT_EVENTS_GAP` | MEDIUM |
| `CLOUDTRAIL_LOG_VALIDATION_DISABLED` | LOW |
| `CLOUDTRAIL_BUCKET_PUBLIC` | CRITICAL |

CloudTrail records AWS API activity. It does not by itself give application-level visibility.

### Secrets Manager (`secrets`) and KMS (`kms`)

| Finding | Severity |
|---|---|
| `SECRETS_ROTATION_DISABLED` | LOW, one finding per Region; secrets owned by another AWS service are skipped |
| `KMS_KEY_PUBLIC` | CRITICAL |
| `KMS_KEY_WILDCARD_PRINCIPAL_CONDITIONED` | MEDIUM |
| `KMS_KEY_CROSS_ACCOUNT` | MEDIUM; HIGH when the other account has administrative actions |

Only customer managed keys are read. fmaws never rotates keys or secrets and does not recommend
doing so automatically. Over-broad *access* to secrets is the IAM finding
`IAM_SECRETS_WILDCARD_ACCESS`.

### RDS (`rds`)

| Finding | Severity |
|---|---|
| `RDS_PUBLIC_OPEN` (public endpoint and security group open on the database port) | CRITICAL |
| `RDS_PUBLICLY_ACCESSIBLE` (public endpoint, security group restricted) | MEDIUM |
| `RDS_UNENCRYPTED` | HIGH if public, MEDIUM in production, LOW otherwise |

DynamoDB has no analyzer of its own: unrestricted table access is an IAM policy problem and is
reported as `IAM_DYNAMODB_WILDCARD_ACCESS`.

## Scoring

```text
score = 100 - sum(penalties), never below 0

points per finding:  CRITICAL 25   HIGH 10   MEDIUM 4   LOW 1   INFO 0
penalty per rule:    min(sum of points of its findings, 2 x points of its worst finding)
```

- **AWS Security Score** uses every finding.
- **Least Privilege Score** uses the findings in the `least-privilege` category: IAM policy
  breadth, administrator access, role trust, cross-account grants and unused roles.

The cap per rule means one issue repeated on fifty resources costs as much as on two, so the
score reflects how many *kinds* of problems exist. Priorities are expressed through severity,
in this order: public exposure, credential compromise risk, administrative access,
cross-account exposure, wildcard permissions, missing MFA, stale credentials, defense in depth.
There are no hidden weights; you can recompute the score from the JSON report.

Ignored findings do not count. Severity overrides do.

## Partial access and failures

Each analyzer ends as completed, skipped or failed, with the reason:

```text
Completed: 8 analyzers
Skipped: 1
Failed: 1
  s3: completed, incomplete, s3:GetBucketPolicy failed for 3 resource(s)
  kms: skipped, eu-west-1: missing permission kms:ListKeys
  rds: failed, AWS returned InternalFailure
```

- A missing permission skips that analyzer (or that Region, or that resource) and the audit
  continues. What could not be read is never reported as clean.
- Expired credentials stop the audit with exit code 3.
- If no analyzer could run, the exit code is 3.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No threshold configured, or no finding at or above it |
| 1 | A finding at or above `--fail-on` (or `audit.fail_on`) |
| 2 | Configuration error, or a threshold is set and the audit is incomplete (see below) |
| 3 | No credentials, expired credentials, or no analyzer could run |

With a threshold, an audit in which an analyzer was skipped for missing permissions or failed
exits 2 instead of 0: a gate should not pass because the tool could not look. Use
`--allow-partial` to accept that on purpose. Analyzers disabled in configuration do not count
as incomplete.

## Tuning

See [configuration](configuration.md#audit-options) for ignored findings and resources, severity
overrides, intentional public buckets, trusted accounts and thresholds per environment.

## Cost

IAM is covered by three calls plus pagination. S3 costs seven calls per bucket, KMS one call
per customer managed key, CloudTrail three calls per trail; the other analyzers make one or two
paginated calls per Region. Requests run with bounded concurrency (`audit.concurrency`, default
4) and adaptive retries. All APIs used are free of charge.

## References

- [IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html)
- [Blocking public access to S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [The confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [CloudTrail best practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html)
