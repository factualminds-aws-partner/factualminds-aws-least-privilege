# Limitations

## A candidate policy is not a proof

fmaws derives a **candidate policy** from configuration and static evidence. It cannot
guarantee that the policy is the mathematically smallest one, or that the application never
needs a permission that was not declared or detected. Code paths that run rarely (error
handling, month-end jobs, disaster recovery) are exactly the ones static evidence misses.

Test a generated policy in a non-production environment and watch for `AccessDenied` before
relying on it.

The planned `fmaws observe` command will add an **observed policy** from real AWS activity and
a **recommended policy** that refines one with the other. It is not part of this version.

## Discovery

- Only literal names are resolved. Terraform variables and expressions, CloudFormation
  intrinsics, generated physical names and values built at run time are not. fmaws reports how
  many names it could not resolve per file.
- Infrastructure-as-code says a resource exists, not what the application does with it.
  Discovered resources get the service default action at LOW confidence and are listed as
  unconfirmed.
- SDK detection looks for literal resource names next to AWS SDK imports and attributes the
  calls found in the same file. With several resources of one service in a file, the calls are
  attributed to all of them and marked unconfirmed.
- Environment heuristics are deliberately narrow to avoid false positives. A DynamoDB table in
  `USERS_TABLE` is not detected (the key does not say DynamoDB); declare it.
- CDK is supported through synthesized templates (`cdk.out`), not CDK source code.
- Terraform modules, `for_each`, `count` and remote state are not followed.

## Policy generation

- The catalog covers the listed services and common data-plane actions. Control-plane actions
  (creating tables, managing queues) are out of scope: an application role should rarely have
  them.
- `dynamodb` `write` includes `BatchWriteItem`, which can also delete items.
- DynamoDB tables encrypted with a customer managed key, and other services not listed under
  `kms_key` in the configuration guide, do not get companion KMS statements. Declare the key
  under `kms` when the caller needs direct key access.
- Secrets Manager ARNs for a secret name end in `-??????`. A secret whose own name ends in a
  hyphen and six characters can be matched by a shorter name's pattern, as described in the
  Secrets Manager documentation. Use the full ARN to be exact.
- Bedrock inference profiles require the foundation model in every destination region, so that
  statement has a region wildcard.
- Resource-based policies (bucket policies, key policies, queue policies), permission
  boundaries, SCPs and session policies are not generated or considered. Cross-account S3 access
  additionally needs the owner's bucket policy.
- Size is checked against the 6,144 character managed policy limit only.

## Validation

- Local validation targets identity policies. It knows which actions support resource-level
  permissions only for the services in the catalog; other actions on `Resource: "*"` are a
  low-severity "verify" finding.
- Condition logic is not evaluated. fmaws recognizes a small number of conditions that certainly
  restrict (`iam:PassedToService` with specific services) and treats everything else as
  unproven.
- IAM Access Analyzer validation checks grammar and best practices. It does not prove that a
  policy is least privilege.

## Audit

- The audit is a focused set of high-signal checks, not a replacement for AWS Security Hub,
  IAM Access Analyzer or a CSPM product.
- It audits one account. Organizations, SCPs, permission boundaries and delegated administrators
  are not evaluated, so an "allowed" permission may in fact be blocked elsewhere.
- Conditions are not fully evaluated. A wildcard principal is treated as not public only when a
  condition demonstrably pins a network, organization, account or source ARN (see
  [audit](audit.md#s3-s3)); every other condition produces a "limited only by its condition"
  finding. `aws:PrincipalOrgID` is accepted without checking that the organization is yours.
- Explicit `Deny` statements are not taken into account, so a grant that a Deny cancels is
  still reported.
- Resource policies are read for S3 buckets, KMS keys and IAM role trust only. Policies on
  individual secrets, queues, topics, Lambda functions and ECR repositories are not read.
- "Unused" relies on the IAM credential report and role last-used data. Unused for
  `audit.unused_days` is not the same as unnecessary; confirm with the owner.
- Root findings in an AWS Organizations member account whose root credentials are centrally
  managed depend on the credential report showing no root password; otherwise the missing-MFA
  finding is reported.
- RDS checks cover DB instances (including Aurora instances), not cluster-level settings,
  snapshots or parameter groups.
- CloudTrail records API activity. It does not provide application-level visibility, and S3 or
  Lambda data events are only recorded when explicitly enabled.
- AWS managed policies other than `AdministratorAccess` are not analyzed for breadth.

## Observe

- Observation is about one principal. If the application runs as several roles, observe each.
- IAM tracks last use per service for everything, but per action only for a subset of actions,
  mostly management actions. Most data-plane permissions therefore come out as *unknown*, not
  *unused*, unless you supply an Access Analyzer generated policy built from a trail that logs
  data events.
- IAM last accessed reports only services the principal can use today, and reflects every
  policy attached to it, not only the candidate.
- Evidence is at action level. `observe` does not check that the resources in the candidate
  match the resources that were used.
- CloudTrail lookup reads management events of a single Region for at most 90 days, is capped
  by `--max-events`, and maps event names to IAM actions by name, which is not exact for every
  service.
- Unused for the period is not unnecessary. The recommended policy only drops unused,
  undeclared permissions after `observe.min_days_for_removal` days, and even then it is a
  recommendation to test, not a guarantee.
