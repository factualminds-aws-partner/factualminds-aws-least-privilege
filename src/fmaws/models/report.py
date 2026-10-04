"""Everything a reporter needs to render the result of a command."""

from typing import Any

from pydantic import BaseModel, Field

from fmaws.models.finding import Finding, Severity
from fmaws.models.policy import Statement
from fmaws.models.requirement import ResourceRequirement

NOT_RUN = "NOT RUN"


class AnalyzerStatus(BaseModel):
    name: str
    status: str  # completed | skipped | failed
    detail: str = ""


class Observation(BaseModel):
    action: str
    status: str  # USED | UNUSED | UNKNOWN | POTENTIALLY MISSING
    statement: str = ""
    last_seen: str | None = None
    source: str = ""
    detail: str = ""
    removed: bool = False


class Report(BaseModel):
    command: str
    policy: dict[str, Any] | None = None
    policy_path: str | None = None
    statements: list[Statement] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    unconfirmed: list[ResourceRequirement] = Field(default_factory=list)
    context: dict[str, str] = Field(default_factory=dict)
    local_validation: str = NOT_RUN
    aws_validation: str = NOT_RUN
    show_explanations: bool = False
    # Audit only.
    analyzers: list[AnalyzerStatus] = Field(default_factory=list)
    scores: dict[str, int] = Field(default_factory=dict)
    ignored: int = 0
    # Observe only.
    observations: list[Observation] = Field(default_factory=list)

    def observed(self, status: str) -> list[Observation]:
        return sorted(
            (o for o in self.observations if o.status == status),
            key=lambda o: (o.action.lower(), o.statement),
        )

    def count(self, severity: Severity) -> int:
        return sum(f.severity is severity for f in self.findings)

    def analyzer_summary(self) -> list[str]:
        """ "Completed: 8 analyzers" lines followed by the reason for everything that did not."""
        lines = [
            f"{label}: {sum(a.status == state for a in self.analyzers)}"
            + (" analyzers" if state == "completed" else "")
            for label, state in (
                ("Completed", "completed"),
                ("Skipped", "skipped"),
                ("Failed", "failed"),
            )
        ]
        lines += [f"  {a.name}: {a.status}, {a.detail}" for a in self.analyzers if a.detail]
        return lines

    @property
    def errors(self) -> int:
        return sum(f.severity.rank >= Severity.HIGH.rank for f in self.findings)

    @property
    def warnings(self) -> int:
        return sum(f.severity is Severity.MEDIUM for f in self.findings)

    @property
    def recommendations(self) -> int:
        return sum(f.severity.rank <= Severity.LOW.rank for f in self.findings)


def status(findings: list[Finding]) -> str:
    return "FAIL" if any(f.severity.rank >= Severity.HIGH.rank for f in findings) else "PASS"
