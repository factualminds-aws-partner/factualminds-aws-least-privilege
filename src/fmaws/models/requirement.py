"""A single piece of evidence that the application needs access to an AWS resource."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


class SourceRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    file: str
    line: int | None = None

    def __str__(self) -> str:
        return self.file if self.line is None else f"{self.file}:{self.line}"


class ResourceRequirement(BaseModel):
    service: str
    resource: str
    intents: tuple[str, ...]
    confidence: Confidence
    source: SourceRef
    reason: str
    # False when the resource was discovered but what the application does with it is a guess.
    intent_confirmed: bool = True
    options: dict[str, Any] = Field(default_factory=dict)
