# AWS permissions

The permissions fmaws itself needs are listed in
[required-aws-permissions.md](required-aws-permissions.md). In short: `generate`, `explain` and
`validate --local-only` need none; `validate` needs `access-analyzer:ValidatePolicy`.

The permissions fmaws *generates* for your application are described in
[generate.md](generate.md), [configuration.md](configuration.md) and
[s3-least-privilege.md](s3-least-privilege.md).
