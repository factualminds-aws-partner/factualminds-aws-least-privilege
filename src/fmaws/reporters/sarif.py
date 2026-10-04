"""SARIF 2.1.0, for GitHub code scanning and other CI security tooling."""

import hashlib
import json
from typing import Any

from fmaws import __version__
from fmaws.models.finding import Finding, Severity
from fmaws.models.report import Report
from fmaws.reporters.base import register

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub maps security-severity to critical / high / medium / low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
# AWS resources have no file. Code scanning requires one, so results point at the policy that
# was validated or, for an audit, at the project configuration.
DEFAULT_ARTIFACT = "fmaws.yaml"


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "name": finding.id.title().replace("_", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.why_it_matters},
        "help": {"text": finding.remediation},
        "helpUri": finding.documentation_url or None,
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "category": finding.category,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", "aws", finding.service],
        },
    }


@register("sarif")
def render_sarif(report: Report) -> str:
    artifact = report.policy_path or DEFAULT_ARTIFACT
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.sorted_findings():
        rules.setdefault(finding.id, _rule(finding))
        fingerprint = hashlib.sha256(f"{finding.id}|{finding.resource}".encode()).hexdigest()
        results.append(
            {
                "ruleId": finding.id,
                "level": _LEVEL[finding.severity],
                "message": {
                    "text": f"{finding.title}. {finding.problem} Fix: {finding.remediation}"
                    + (f" Resource: {finding.resource}" if finding.resource else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {"name": finding.resource or finding.service, "kind": "resource"}
                        ],
                    }
                ],
                "partialFingerprints": {"fmawsFindingHash/v1": fingerprint},
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "resource": finding.resource,
                },
            }
        )
    incomplete = [a for a in report.analyzers if a.incomplete]
    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fmaws",
                        "version": __version__,
                        "informationUri": "https://github.com/factualminds-aws-partner/"
                        "factualminds-aws-least-privilege",
                        "rules": [
                            {k: v for k, v in rule.items() if v is not None}
                            for rule in rules.values()
                        ],
                    }
                },
                "results": results,
                # Code scanning must not show an audit that could not look as a clean run.
                "invocations": [
                    {
                        "executionSuccessful": not incomplete,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": f"{a.name}: {a.status}, {a.detail}"},
                            }
                            for a in incomplete
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
