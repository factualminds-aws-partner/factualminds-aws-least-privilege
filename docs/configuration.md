# Configuration

Configuration is optional. Without it, fmaws discovers resources from the project. With it,
you get an exact, HIGH-confidence policy.

fmaws reads `fmaws.yaml` from the current directory (or `--config PATH`) and layers it over the
optional user-level file `~/.config/fmaws/config.yaml`. Project values win.

## Full example

```yaml
application:
  name: ecommerce-agent
  environment: production

aws:
  region: ap-south-1          # used in ARNs
  account_id: "111122223333"  # used in ARNs; quote it
  profile: production         # optional AWS profile
  partition: aws              # aws | aws-cn | aws-us-gov

resources:
  s3:
    - bucket: ecommerce-assets
      prefixes: [uploads/, product-images/]
      actions: [read, write, list]
      kms_key: 1234abcd-12ab-34cd-56ef-1234567890ab
  dynamodb:
    - table: customers
      actions: [read]
  sqs:
    - queue: order-processing
      actions: [send, receive]
  bedrock:
    - models: [anthropic.claude-3-haiku-20240307-v1:0]
      actions: [invoke]

policy:
  include_conditions: true
  wildcard_action_threshold: warning   # info | warning | error

discovery:
  enabled: true
  paths: []       # empty = whole project; otherwise files/directories relative to the project
  detectors: []   # empty = all; otherwise any of arn, env, cloudformation, serverless, terraform, docker, sdk
```

## Resources

Every entry names a resource and lists `actions`. The resource can be a name or a full ARN. A
full ARN is used verbatim. For a name, fmaws builds the ARN from `aws.region` and
`aws.account_id`. Use the plural key to list several resources with the same actions
(`tables: [a, b]`).

| Service | Key | Actions |
|---|---|---|
| `s3` | `bucket` | `read`, `write`, `delete`, `list` (see [S3](s3-least-privilege.md)) |
| `dynamodb` | `table` | `read`, `write`, `delete`, `list` |
| `sqs` | `queue` | `send`, `receive`, `read`, `purge`, `list` |
| `sns` | `topic` | `publish`, `subscribe`, `list` |
| `secretsmanager` | `secret` | `read`, `write`, `delete`, `list` |
| `kms` | `key` (key ID, key ARN or `alias/name`) | `encrypt`, `decrypt` (`write`, `read` are synonyms), `list` |
| `lambda` | `function` | `invoke`, `list` |
| `eventbridge` | `bus` | `publish` |
| `logs` | `log_group` | `write`, `read` |
| `ses` | `identity` | `send` |
| `bedrock` | `model` (model ID or inference profile ID) | `invoke`, `list` |
| `rds` | `db_user` (`<DbiResourceId>/<database user>`) | `connect` |
| `rds_data` | `cluster` | `execute`, `transaction` |

Notes:

- `list` on anything but S3 maps to an account-level list operation that AWS only authorizes on
  `Resource: "*"`. fmaws puts it in its own statement and explains why.
- `kms_key: <key id or ARN>` on an `s3`, `sqs`, `sns` or `secretsmanager` entry adds the KMS
  permissions that the declared actions need, scoped to that key and (with
  `policy.include_conditions`) to `kms:ViaService`.
- A KMS alias is authorized as `key/*` with a `kms:ResourceAliases` condition, because IAM
  authorizes keys, not aliases.
- A Bedrock cross-region inference profile ID (`us.anthropic...`) produces the inference profile
  ARN plus the foundation model ARN in any region, which is what Bedrock requires.
- If an entry has no `actions`, the service default is used (for example `read` for DynamoDB,
  `publish` for SNS).

Resource names may not contain wildcards, whitespace or quotes. fmaws rejects them rather than
writing a broader policy than you asked for.

## Policy options

- `include_conditions` (default `true`): add `kms:ViaService` and `s3:ResourceAccount`
  conditions. The S3 `s3:prefix` condition is always written because it is what limits listing
  to a folder.
- `deny_public_access` is accepted for compatibility with published examples and has no
  effect: a generated identity policy never grants public access.
- `wildcard_action_threshold` (default `warning`): severity of `service:*` actions in local
  validation. `iam:*`, `sts:*`, `kms:*` and `organizations:*` are always errors.

## Discovery options

`discovery.paths` entries must stay inside the project directory. fmaws always skips `.git`,
`node_modules`, `vendor`, virtual environments, `.terraform`, build directories, files larger
than 2 MB, symlinks that point outside the project, the configuration file and the output file.

## Audit options

```yaml
audit:
  enabled_analyzers: []        # empty = all: iam_root, iam_credentials, iam_policies, iam_roles,
                               # s3, network, cloudtrail, secrets, kms, rds
  regions: []                  # Regions to audit when --region / --all-regions are not given
  environment: production      # defaults to application.environment, then production
  fail_on: [critical, high]    # threshold when --fail-on is not given
  production:
    fail_on: [critical, high]  # overrides fail_on in production
  non_production:
    fail_on: [critical]        # overrides fail_on everywhere else
  ignored_findings:
    - S3_LOGGING_DISABLED
  ignored_resources:           # exact resources or shell-style patterns
    - arn:aws:s3:::legacy-*
  severity_overrides:
    IAM_ROLE_UNUSED: info
  intentional_public:          # buckets that are public on purpose (names, ARNs or patterns)
    - marketing-site
  trusted_accounts:            # account IDs inside your trust boundary
    - "999900001111"
  max_access_key_age_days: 90
  unused_days: 90              # credentials, users and roles idle longer than this are reported
  concurrency: 4               # parallel AWS requests (1-16)
```

- `fail_on` takes one severity or a list; the lowest listed severity is the threshold.
- `intentional_public` turns a public **read** finding into the informational
  `S3_PUBLIC_READ_INTENTIONAL`. Public write and delete are never excused.
- `trusted_accounts` suppresses cross-account findings for role trust, bucket policies and KMS
  key policies.
- Ignored findings are counted in the report so that suppression stays visible.

## Observe options

```yaml
observe:
  principal: arn:aws:iam::111122223333:role/ecommerce-agent   # role or user the app runs as
  days: 30                    # observation period
  min_days_for_removal: 90    # an unused permission is only dropped after this many days
  cloudtrail: false           # also read CloudTrail management events
  max_events: 2000            # cap on CloudTrail events read
```

See [observe](observe.md).

## Unknown keys

Unknown or misspelled keys anywhere in the file are a configuration error (exit code 2), so a
typo such as `polcy:` cannot silently fall back to defaults.
