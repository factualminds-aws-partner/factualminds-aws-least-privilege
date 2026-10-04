"""CloudTrail coverage. CloudTrail records API activity, not application-level activity."""

from typing import Any

from fmaws.audit.base import AuditContext, register
from fmaws.audit.findings import make
from fmaws.models.finding import Finding


def _all_management_events(selectors: dict[str, Any]) -> bool:
    for selector in selectors.get("EventSelectors") or []:
        if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
            return True
    for selector in selectors.get("AdvancedEventSelectors") or []:
        fields = {f.get("Field"): f for f in selector.get("FieldSelectors", [])}
        category = fields.get("eventCategory", {}).get("Equals", [])
        if "Management" in category and "readOnly" not in fields:
            return True
    return False


class CloudTrail:
    name = "cloudtrail"
    regional = False

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        account_arn = f"arn:{ctx.partition}:cloudtrail:*:{ctx.account}:trail/*"
        trails: dict[str, dict[str, Any]] = {}
        listings = ctx.map(
            lambda r: ctx.call("cloudtrail", "describe_trails", r, includeShadowTrails=True),
            ctx.regions,
        )
        for listed in listings:
            for trail in listed.get("trailList", []):
                trails.setdefault(trail["TrailARN"], trail)
        if not trails:
            return [
                make(
                    "CLOUDTRAIL_NO_TRAIL", account_arn, f"No trail covers {', '.join(ctx.regions)}."
                )
            ]

        findings: list[Finding] = []
        logging: list[dict[str, Any]] = []
        management = False
        for arn, trail in sorted(trails.items()):
            home = trail.get("HomeRegion") or ctx.home_region
            status = ctx.optional("cloudtrail", "get_trail_status", home, Name=arn)
            # An unreadable status is not evidence that the trail is off.
            if status is not None and not status.get("IsLogging"):
                continue
            logging.append(trail)
            selectors = ctx.optional("cloudtrail", "get_event_selectors", home, TrailName=arn)
            management = management or selectors is None or _all_management_events(selectors)
            if not trail.get("LogFileValidationEnabled"):
                findings.append(
                    make(
                        "CLOUDTRAIL_LOG_VALIDATION_DISABLED",
                        arn,
                        "Log file validation is disabled.",
                    )
                )
            bucket = trail.get("S3BucketName")
            if bucket:
                policy_status = ctx.optional(
                    "s3", "get_bucket_policy_status", missing=("NoSuchBucketPolicy",), Bucket=bucket
                )
                if (policy_status or {}).get("PolicyStatus", {}).get("IsPublic"):
                    findings.append(
                        make(
                            "CLOUDTRAIL_BUCKET_PUBLIC",
                            f"arn:{ctx.partition}:s3:::{bucket}",
                            f"The log bucket of trail {trail.get('Name', arn)} is public.",
                        )
                    )

        uncovered = [
            r for r in ctx.regions
            if not any(t.get("IsMultiRegionTrail") or t.get("HomeRegion") == r for t in logging)
        ]  # fmt: skip
        if uncovered:
            findings.append(
                make(
                    "CLOUDTRAIL_NOT_LOGGING",
                    account_arn,
                    f"No logging trail covers: {', '.join(uncovered)}.",
                    evidence={"regions": uncovered},
                )
            )
        if logging and not any(t.get("IsMultiRegionTrail") for t in logging):
            findings.append(
                make(
                    "CLOUDTRAIL_NOT_MULTI_REGION",
                    account_arn,
                    "Every logging trail is limited to a single Region.",
                )
            )
        if logging and not management:
            findings.append(
                make(
                    "CLOUDTRAIL_MANAGEMENT_EVENTS_GAP",
                    account_arn,
                    "No logging trail records both read and write management events.",
                )
            )
        return findings


register(CloudTrail())
