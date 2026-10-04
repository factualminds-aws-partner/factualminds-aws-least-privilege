import os
import sys
from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from fmaws.models.finding import Severity
from fmaws.models.report import Report
from fmaws.reporters.base import CANDIDATE_NOTICE, OBSERVE_LABELS, UNUSED_NOTICE, register
from fmaws.utils.redact import mask_account

_SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}
_STATUS_STYLE = {"PASS": "green", "FAIL": "bold red"}
_OBSERVE_STYLE = {
    "USED": "green",
    "UNUSED": "yellow",
    "UNKNOWN": "dim",
    "POTENTIALLY MISSING": "bold red",
}


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


@register("console")
def render_console(report: Report) -> str:
    buffer = StringIO()
    width = int(os.environ.get("COLUMNS", "0")) or 110
    console = Console(file=buffer, force_terminal=sys.stdout.isatty(), width=width, highlight=False)

    def line(text: str = "", style: str = "") -> None:
        console.print(Text(text, style=style))

    if report.policy_path and report.command == "observe":
        line(f"Recommended policy: {report.policy_path}", "bold")
    elif report.policy_path:
        line(f"Generated policy: {report.policy_path}" if report.command == "generate"
             else f"Policy: {report.policy_path}", "bold")  # fmt: skip
    if report.context:
        account = mask_account(report.context.get("account", "*"))
        line(f"Account: {account}  Region: {report.context.get('region', '*')}", "dim")
    line()

    if report.statements and not report.show_explanations:
        table = Table(show_lines=True, expand=True)
        for column in ("Actions", "Resources", "Confidence"):
            table.add_column(column, overflow="fold")
        for statement in report.statements:
            resources = list(statement.resources)
            if statement.conditions:
                resources.append(f"Condition: {statement.conditions}")
            table.add_row(
                Text("\n".join(statement.actions)),
                Text("\n".join(resources)),
                Text(statement.confidence.value),
            )
        console.print(table)
        line("Run with --explain to see why each statement exists.", "dim")
        line()

    if report.statements and report.show_explanations:
        for statement in report.statements:
            line(", ".join(statement.actions), "bold")
            for resource in statement.resources:
                line(f"  Resource: {resource}")
            if statement.conditions:
                line(f"  Condition: {statement.conditions}")
            for explanation in statement.explanations:
                line("  Reason:")
                line(f"    {explanation.reason}")
                line(f"  Source: {explanation.source}")
                line(f"  Confidence: {explanation.confidence.value}")
            line()

    if report.command == "observe":
        line(f"Principal: {report.context.get('principal', '')}", "bold")
        line(f"Observation period: {report.context.get('days', '')} days")
        line(f"Sources: {report.context.get('sources', '')}")
        line()
        table = Table(show_lines=False, expand=True)
        for column in ("Status", "Action", "Statement", "Last seen", "Evidence"):
            table.add_column(column, overflow="fold")
        for status, _ in OBSERVE_LABELS:
            for item in report.observed(status):
                table.add_row(
                    Text(status, style=_OBSERVE_STYLE[status]),
                    Text(item.action),
                    Text(item.statement),
                    Text(item.last_seen or "-"),
                    Text(item.detail),
                )
        console.print(table)
        line()
        for status, label in OBSERVE_LABELS:
            line(f"{label}: {len(report.observed(status))}")
        removed = [o for o in report.observations if o.removed]
        line()
        if removed:
            line("Removed from the recommended policy:", "bold")
            for item in removed:
                line(f"  {item.action} ({item.statement}): {item.detail}")
        else:
            line("No permission was removed from the recommended policy.")
        line()
        line(UNUSED_NOTICE, "dim")
    elif report.command == "audit":
        line(f"AWS Security Score: {report.scores.get('security', 0)}/100", "bold")
        line(f"Least Privilege Score: {report.scores.get('least_privilege', 0)}/100", "bold")
        line()
        for summary in report.analyzer_summary():
            line(summary)
        line()
        line("Findings:", "bold")
        for severity in Severity:
            line(f"{report.count(severity)} {severity.value.lower()}")
        if report.ignored:
            line(f"{report.ignored} ignored by configuration", "dim")
    else:
        line(f"Local validation: {report.local_validation}",
             _STATUS_STYLE.get(report.local_validation, ""))  # fmt: skip
        line(f"AWS IAM Access Analyzer: {report.aws_validation}",
             _STATUS_STYLE.get(report.aws_validation, "dim"))  # fmt: skip
        line()
        line("Findings:", "bold")
        line(_plural(report.errors, "error"))
        line(_plural(report.warnings, "warning"))
        line(_plural(report.recommendations, "recommendation"))

    for finding in sorted(report.findings, key=lambda f: (-f.severity.rank, f.id, f.resource)):
        line()
        heading = Text()
        heading.append(finding.severity.value, style=_SEVERITY_STYLE[finding.severity.value])
        heading.append(f"  {finding.service.upper()}")
        console.print(heading)
        line(finding.title, "bold")
        if finding.resource:
            line(f"Resource: {finding.resource}")
        line()
        line("Problem:")
        line(finding.problem)
        line()
        line("Fix:")
        line(finding.remediation)
        line()
        line(f"Confidence: {finding.confidence.value}")

    if report.unconfirmed:
        line()
        line("Unconfirmed access (resource detected, usage assumed):", "bold")
        for requirement in report.unconfirmed:
            line(f"  {requirement.service} {requirement.resource}: assumed "
                 f"{', '.join(requirement.intents)} ({requirement.source})")  # fmt: skip
        line("  Declare these in fmaws.yaml with the actions the application really performs.")
    if report.notes:
        line()
        line("Notes:", "bold")
        for note in report.notes:
            line(f"  - {note}")
    if report.policy is not None:
        line()
        line(CANDIDATE_NOTICE, "dim")
    return buffer.getvalue()
