"""Security scores. The model is deliberately small enough to recompute by hand.

score = 100 - sum of penalties, never below 0.

A finding costs its severity's points: CRITICAL 25, HIGH 10, MEDIUM 4, LOW 1, INFO 0.
All findings with the same ID together cost at most twice the points of the most severe one,
so one issue repeated on fifty resources cannot zero the score by itself.

Priorities (public exposure, credential compromise, administrative access, cross-account
exposure, wildcards, MFA, stale credentials, defense in depth) are expressed through the
severity each rule assigns, not through hidden weights.
"""

from fmaws.audit.findings import LEAST_PRIVILEGE
from fmaws.models.finding import Finding, Severity

POINTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
REPEAT_CAP = 2


def score(findings: list[Finding]) -> int:
    by_rule: dict[str, list[int]] = {}
    for finding in findings:
        by_rule.setdefault(finding.id, []).append(POINTS[finding.severity])
    penalty = sum(min(sum(points), REPEAT_CAP * max(points)) for points in by_rule.values())
    return max(0, 100 - penalty)


def scores(findings: list[Finding]) -> dict[str, int]:
    return {
        "security": score(findings),
        "least_privilege": score([f for f in findings if f.category == LEAST_PRIVILEGE]),
    }
