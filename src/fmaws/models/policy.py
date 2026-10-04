"""IAM policy statements carrying the explanation of why they exist."""

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from fmaws.models.requirement import Confidence

Conditions = dict[str, dict[str, list[str]]]

POLICY_VERSION = "2012-10-17"


class Explanation(BaseModel):
    model_config = ConfigDict(frozen=True)

    reason: str
    source: str
    confidence: Confidence


class Statement(BaseModel):
    sid: str = ""
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    conditions: Conditions = Field(default_factory=dict)
    explanations: tuple[Explanation, ...] = ()

    @property
    def confidence(self) -> Confidence:
        """Weakest evidence behind the statement."""
        return min(
            (e.confidence for e in self.explanations), key=lambda c: c.rank, default=Confidence.LOW
        )

    def to_iam(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.sid:
            out["Sid"] = self.sid
        out["Effect"] = "Allow"
        out["Action"] = self.actions[0] if len(self.actions) == 1 else list(self.actions)
        out["Resource"] = self.resources[0] if len(self.resources) == 1 else list(self.resources)
        if self.conditions:
            out["Condition"] = self.conditions
        return out


class PolicyDocument(BaseModel):
    statements: tuple[Statement, ...]

    def to_iam(self) -> dict[str, Any]:
        return {"Version": POLICY_VERSION, "Statement": [s.to_iam() for s in self.statements]}

    def to_json(self) -> str:
        return json.dumps(self.to_iam(), indent=2) + "\n"
