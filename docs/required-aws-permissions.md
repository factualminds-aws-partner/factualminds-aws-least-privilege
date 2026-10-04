# Required AWS permissions

fmaws does not need `AdministratorAccess` or any write permission.

| Command | AWS permissions |
|---|---|
| `fmaws generate` | None. No AWS call is made |
| `fmaws generate --profile NAME` | `sts:GetCallerIdentity` (allowed for every principal by default) |
| `fmaws generate --validate` | `sts:GetCallerIdentity`, `access-analyzer:ValidatePolicy` |
| `fmaws explain` | None |
| `fmaws validate FILE --local-only` | None |
| `fmaws validate FILE` | `access-analyzer:ValidatePolicy` |
| `fmaws audit` | The read-only actions below. With fewer permissions the audit still runs and reports which analyzers were skipped |
| `fmaws audit --all-regions` | Additionally `ec2:DescribeRegions` (included below) |
| `fmaws observe` | `sts:GetCallerIdentity`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails` |
| `fmaws observe --cloudtrail` | Additionally `cloudtrail:LookupEvents` |
| `fmaws observe --access-analyzer-job ID` | Additionally `access-analyzer:GetGeneratedPolicy` |
| `fmaws doctor` | `sts:GetCallerIdentity`; `access-analyzer:ValidatePolicy` is probed and reported as a warning if missing |

Machine-readable policy: [`permissions/validate-policy.json`](../permissions/validate-policy.json).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FmawsValidate",
      "Effect": "Allow",
      "Action": "access-analyzer:ValidatePolicy",
      "Resource": "*"
    }
  ]
}
```

`access-analyzer:ValidatePolicy` does not support resource-level permissions, which is why the
resource is `*`. It does not require an analyzer to exist in the account and it is free of
charge.

`sts:GetCallerIdentity` needs no policy statement: AWS allows it for every authenticated
principal.

## Observe

Machine-readable policy: [`permissions/observe-policy.json`](../permissions/observe-policy.json),
generated from the allow-list in `fmaws/observe.py`.

`iam:GenerateServiceLastAccessedDetails` asks IAM to compute a report for one principal. Like
the credential report it changes no resource. fmaws does not call
`access-analyzer:StartPolicyGeneration`.

## Audit

Machine-readable policy: [`permissions/audit-readonly-policy.json`](../permissions/audit-readonly-policy.json).
It is generated from the allow-list of operations in `fmaws/audit/base.py`; the audit refuses
to call anything that is not on that list, and a test keeps the file and the list identical.

| Analyzer | Actions |
|---|---|
| `iam_root` | `iam:GetAccountSummary`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| `iam_credentials` | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| `iam_policies`, `iam_roles` | `iam:GetAccountAuthorizationDetails` |
| `s3` | `s3:ListAllMyBuckets`, `s3:GetAccountPublicAccessBlock`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketOwnershipControls`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`, `s3:GetEncryptionConfiguration` |
| `network` | `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces` |
| `cloudtrail` | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, `s3:GetBucketPolicyStatus` |
| `secrets` | `secretsmanager:ListSecrets` |
| `kms` | `kms:ListKeys`, `kms:ListAliases`, `kms:GetKeyPolicy` |
| `rds` | `rds:DescribeDBInstances`, `ec2:DescribeSecurityGroups` |

`iam:GenerateCredentialReport` asks IAM to refresh the account's credential report. It is the
only action that is not a pure read; it changes no resource and is part of the AWS managed
`SecurityAudit` policy. fmaws never reads secret values, object contents or key material.

The AWS managed policy `SecurityAudit` covers every action above if you prefer it to a custom
policy.

References:
[Actions for IAM Access Analyzer](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamaccessanalyzer.html),
[GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
