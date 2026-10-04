"""Normalized finding shared by policy validation and (later) the account audit."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from fmaws.models.requirement import Confidence


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


class Finding(BaseModel):
    id: str
    severity: Severity
    category: str
    service: str
    resource: str
    title: str
    problem: str
    why_it_matters: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str
    remediation: str
    documentation_url: str = ""
    confidence: Confidence = Confidence.HIGH
    is_auto_fixable: bool = False


def finding_order(finding: Finding) -> tuple[int, str, str]:
    """Most severe first, then stable by rule and resource."""
    return (-finding.severity.rank, finding.id, finding.resource)
