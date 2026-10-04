# fmaws observe

```bash
fmaws observe --principal arn:aws:iam::111122223333:role/ecommerce-agent
fmaws observe --principal role/ecommerce-agent --days 90
fmaws observe --principal role/ecommerce-agent --policy current-policy.json
fmaws observe --principal role/ecommerce-agent --cloudtrail
fmaws observe --principal role/ecommerce-agent --days 120 --output recommended-policy.json
```

`observe` compares a **candidate policy** with what one IAM role or user actually did, and
reports each permission as:

| Status | Meaning |
|---|---|
| Used permission | There is evidence of use inside the observation period |
| Unused permission | A source that tracks the action, or its whole service, shows no use in the period |
| Unknown permission | No evidence source can tell either way |
| Potentially missing permission | The principal used, or was denied, something the candidate does not allow |

**Unused during the observation period is not the same as unnecessary.** A permission used by a
monthly job, an error path or a disaster recovery procedure looks unused in a 30-day window.
And *unknown* is not *unused*: most data-plane actions (`s3:GetObject`, `dynamodb:GetItem`,
`sqs:SendMessage`) are not tracked individually by IAM and are not management events in
CloudTrail, so for them the honest answer is usually "unknown".

## The three policies

| Policy | Source |
|---|---|
| Candidate | `fmaws generate` (configuration and static analysis), or `--policy FILE` |
| Observed | What AWS recorded for the principal (the sources below) |
| Recommended | The candidate, refined by the observation under the rules below (`--output`) |

## Inputs

- `--principal`: the role or user the application runs as. A full ARN, `role/NAME` or
  `user/NAME`. Can be set as `observe.principal` in `fmaws.yaml`.
- The candidate policy: by default the policy `fmaws generate` produces for the current
  directory; `--policy FILE` compares an existing policy instead.
- `--days`: the observation period (default 30, `observe.days`).

## Evidence sources

| Source | Enabled | Cost | What it knows |
|---|---|---|---|
| IAM last accessed | always | 2 API calls and a short poll | Last use per service; per action for the actions IAM tracks (mostly management actions). Up to 400 days back |
| CloudTrail `LookupEvents` | `--cloudtrail` | 1 call per 50 events, paced under the 2 requests/second quota, capped by `--max-events` (default 2000) | Management events of one Region, at most 90 days back, including denied calls |
| Observed policy | `--observed-policy FILE` | none | Any policy that describes observed activity |
| Access Analyzer generated policy | `--access-analyzer-job ID` | 1 API call | The result of an IAM Access Analyzer policy generation job |

Notes on the sources:

- IAM last accessed only reports services the principal can use **today**. A candidate
  permission for a service the principal has no access to yet is "unknown".
- CloudTrail lookup cannot filter by role on the server, so for a role fmaws reads the
  Region's recent events and keeps those issued by that role. In a busy account the
  `--max-events` cap is reached quickly; fmaws says so when it happens. For users the lookup
  is filtered server-side.
- CloudTrail event names are mapped to IAM actions by name. That is right for most management
  events and wrong for a few; treat a "potentially missing" entry from CloudTrail as a lead.
- fmaws does **not** start an Access Analyzer policy generation job. Starting one requires a
  service role with access to your CloudTrail bucket and is not a read-only action. Start it
  yourself (console or `aws accessanalyzer start-policy-generation`) and pass the job ID; that
  is the most complete evidence source, because it reads the trail itself.

## Recommended policy

`--output FILE` writes the recommended policy. It is the candidate with an action removed only
when **all** of these hold:

1. its status is *unused* (never *unknown*),
2. the observation period is at least `observe.min_days_for_removal` (default 90 days),
3. the permission was **not declared** in `fmaws.yaml`.

Every removal is listed in the report. A statement that combines declared and discovered
resources counts as declared. `NotAction` statements cannot be observed action by action; they
are reported as unknown and always kept unchanged. With the default 30-day period nothing is removed and
the report says so. Permissions you declared explicitly are never removed by observation; if
they show as unused, that is information for you to act on in `fmaws.yaml`.

When the candidate comes from `--policy FILE` there is no declaration to protect, so rule 3
does not apply.

## Example

```text
Principal: arn:aws:iam::111122223333:role/app
Observation period: 30 days
Sources: IAM last accessed

 Status   Action            Statement  Last seen   Evidence
 UNUSED   s3:PutObject      S3         -           IAM tracks this action: never used in the
                                                   tracking period.
 UNKNOWN  dynamodb:GetItem  Tables     2026-10-03  The dynamodb service was used, but IAM does
                                                   not track this action individually.
 USED     s3:GetObject      S3         2026-10-02  Used in the period.

Potentially missing permission: 0
Unused permission: 1
Unknown permission: 1
Used permission: 1

No permission was removed from the recommended policy.
```

## Permissions

`iam:GenerateServiceLastAccessedDetails` and `iam:GetServiceLastAccessedDetails`; with
`--cloudtrail` also `cloudtrail:LookupEvents`; with `--access-analyzer-job` also
`access-analyzer:GetGeneratedPolicy`. See
[required-aws-permissions.md](required-aws-permissions.md).

## Exit codes

0 on success, 2 for configuration or runtime errors (no principal, no candidate policy,
unreadable policy file), 3 for missing credentials or permissions.

## References

- [Refining permissions using last accessed information](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html)
- [IAM action last accessed information services and actions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed-action-last-accessed.html)
- [IAM Access Analyzer policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)
- [CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)
