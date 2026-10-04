from fmaws.models.finding import Severity
from fmaws.models.report import NOT_RUN, Report
from fmaws.reporters.base import CANDIDATE_NOTICE, OBSERVE_LABELS, UNUSED_NOTICE, register
from fmaws.utils.redact import mask_account


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


@register("markdown")
def render_markdown(report: Report) -> str:
    lines = [f"# fmaws {report.command} report", ""]
    if report.policy_path:
        lines += [f"Policy: `{report.policy_path}`", ""]
    if report.context:
        account = mask_account(report.context.get("account", "*"))
        lines += [f"Account: `{account}` · Region: `{report.context.get('region', '*')}`", ""]
    if report.command == "observe":
        lines += [
            f"- Principal: `{report.context.get('principal', '')}`",
            f"- Observation period: {report.context.get('days', '')} days",
            f"- Sources: {report.context.get('sources', '')}",
            "",
        ]
        lines += [f"- {label}: {len(report.observed(status))}" for status, label in OBSERVE_LABELS]
        lines += [
            "",
            "| Status | Action | Statement | Last seen | Evidence |",
            "|---|---|---|---|---|",
        ]
        for status, _ in OBSERVE_LABELS:
            lines += [
                f"| {status} | `{o.action}` | {o.statement} | {o.last_seen or '-'} "
                f"| {_cell(o.detail)} |"
                for o in report.observed(status)
            ]
        removed = [o for o in report.observations if o.removed]
        lines += ["", "## Removed from the recommended policy", ""]
        lines += [f"- `{o.action}` ({o.statement})" for o in removed] or ["Nothing was removed."]
        lines += ["", f"> {UNUSED_NOTICE}", ""]
    elif report.command == "audit":
        counts = ", ".join(f"{report.count(s)} {s.value.lower()}" for s in Severity)
        lines += [
            f"- AWS Security Score: **{report.scores.get('security', 0)}/100**",
            f"- Least Privilege Score: **{report.scores.get('least_privilege', 0)}/100**",
            f"- Findings: {counts}" + (f" ({report.ignored} ignored)" if report.ignored else ""),
            "",
            "```text",
            *report.analyzer_summary(),
            "```",
            "",
        ]
    else:
        lines += [
            f"- Local validation: **{report.local_validation}**",
            f"- AWS IAM Access Analyzer: **{report.aws_validation}**",
            f"- Findings: {report.errors} errors, {report.warnings} warnings, "
            f"{report.recommendations} recommendations",
            "",
        ]
    if report.statements:
        lines += ["## Statements", ""]
        for statement in report.statements:
            lines += [f"### {statement.sid or 'Statement'}", ""]
            lines += [f"- Actions: {', '.join(f'`{a}`' for a in statement.actions)}"]
            lines += [f"- Resources: {', '.join(f'`{r}`' for r in statement.resources)}"]
            if statement.conditions:
                lines += [f"- Conditions: `{statement.conditions}`"]
            lines += [f"- Confidence: {statement.confidence.value}", ""]
            lines += ["| Reason | Source | Confidence |", "|---|---|---|"]
            lines += [
                f"| {_cell(e.reason)} | `{e.source}` | {e.confidence.value} |"
                for e in statement.explanations
            ]
            lines.append("")
    if report.findings:
        lines += ["## Findings", ""]
        for finding in report.sorted_findings():
            lines += [f"### {finding.severity.value}: {finding.title}", ""]
            if finding.resource:
                lines += [f"- Resource: `{finding.resource}`"]
            lines += [
                f"- Problem: {finding.problem}",
                f"- Why it matters: {finding.why_it_matters}",
                f"- Fix: {finding.remediation}",
                f"- Confidence: {finding.confidence.value}",
            ]
            if finding.documentation_url:
                lines += [f"- Reference: <{finding.documentation_url}>"]
            lines.append("")
    if report.unconfirmed:
        lines += ["## Unconfirmed access", ""]
        lines += ["The resource was detected but what the application does with it is assumed."]
        lines += [""]
        lines += [
            f"- `{r.service}` `{r.resource}`: assumed {', '.join(r.intents)} ({r.source})"
            for r in report.unconfirmed
        ]
        lines.append("")
    if report.notes:
        lines += ["## Notes", ""] + [f"- {note}" for note in report.notes] + [""]
    if report.policy is not None and report.aws_validation == NOT_RUN:
        lines += ["Run with `--validate` to check the policy with IAM Access Analyzer.", ""]
    if report.policy is not None:
        lines += [f"> {CANDIDATE_NOTICE}", ""]
    return "\n".join(lines)
