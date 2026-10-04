import json

from fmaws.models.finding import Severity
from fmaws.models.report import Report
from fmaws.reporters.base import CANDIDATE_NOTICE, OBSERVE_LABELS, UNUSED_NOTICE, register


@register("json")
def render_json(report: Report) -> str:
    data = report.model_dump(mode="json", exclude={"show_explanations"})
    data["summary"] = {
        "errors": report.errors,
        "warnings": report.warnings,
        "recommendations": report.recommendations,
    }
    if report.command == "audit":
        data["summary"] = {s.value.lower(): report.count(s) for s in Severity}
        data["summary"]["ignored"] = report.ignored
    if report.command == "observe":
        data["summary"] = {
            status.lower().replace(" ", "_"): len(report.observed(status))
            for status, _ in OBSERVE_LABELS
        }
        data["notice"] = UNUSED_NOTICE
    if report.policy is not None:
        data["notice"] = CANDIDATE_NOTICE
    return json.dumps(data, indent=2) + "\n"
