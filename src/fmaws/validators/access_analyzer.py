"""IAM Access Analyzer policy validation. Every finding AWS returns is reported."""

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from fmaws.aws.session import AWSClientProvider, translate
from fmaws.models.finding import Finding, Severity

_SEVERITY = {
    "ERROR": Severity.HIGH,
    "SECURITY_WARNING": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "SUGGESTION": Severity.LOW,
}
_WHY = {
    "ERROR": "IAM rejects the policy or the statement has no effect.",
    "SECURITY_WARNING": "AWS considers the access granted by this statement overly permissive.",
    "WARNING": "The policy does not follow AWS policy authoring best practices.",
    "SUGGESTION": "AWS recommends this improvement to the policy.",
}
DOCS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html"
FALLBACK_REGION = "us-east-1"


def _location(finding: dict[str, Any]) -> str:
    locations = finding.get("locations") or []
    if not locations:
        return ""
    parts: list[str] = []
    for element in locations[0].get("path", []):
        if "index" in element:
            parts[-1:] = [f"{parts[-1] if parts else ''}[{element['index']}]"]
        elif "value" in element:
            parts.append(str(element["value"]))
        elif "substring" not in element:
            parts.append(str(next(iter(element.values()), "")))
    return ".".join(parts)


def validate_with_access_analyzer(provider: AWSClientProvider, policy_json: str) -> list[Finding]:
    """One paginated ``access-analyzer:ValidatePolicy`` call for an identity policy."""
    client = provider.client("accessanalyzer", provider.region or FALLBACK_REGION)
    raw: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"policyDocument": policy_json, "policyType": "IDENTITY_POLICY"}
        if token:
            kwargs["nextToken"] = token
        try:
            response = client.validate_policy(**kwargs)
        except (BotoCoreError, ClientError) as exc:
            raise translate(exc, "calling access-analyzer:ValidatePolicy") from exc
        raw.extend(response.get("findings", []))
        token = response.get("nextToken")
        if not token:
            break

    findings: list[Finding] = []
    for item in raw:
        kind = item.get("findingType", "WARNING")
        details = item.get("findingDetails", "")
        link = item.get("learnMoreLink", DOCS)
        findings.append(
            Finding(
                id=f"ACCESS_ANALYZER_{item.get('issueCode', 'FINDING')}",
                severity=_SEVERITY.get(kind, Severity.MEDIUM),
                category="policy",
                service="access-analyzer",
                resource=_location(item),
                title=f"Access Analyzer {kind.replace('_', ' ').lower()}: "
                f"{item.get('issueCode', 'finding')}",
                problem=details,
                why_it_matters=_WHY.get(kind, _WHY["WARNING"]),
                evidence={"findingType": kind, "locations": item.get("locations", [])},
                recommendation=details,
                remediation=f"{details} See {link}",
                documentation_url=link,
            )
        )
    return findings
