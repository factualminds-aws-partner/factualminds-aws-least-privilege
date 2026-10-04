"""Observed access: compare a candidate policy with what a principal actually did.

"Unused during the observation period" is evidence, not proof, that a permission is
unnecessary. Nothing here removes a permission without saying so.
"""

import json
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from fmaws.aws.session import AWSClientProvider, read_only_manifest, translate
from fmaws.errors import ConfigError, FmawsError
from fmaws.models.report import MISSING, UNKNOWN, UNUSED, USED, Observation
from fmaws.validators.local import action_allows, as_list

# Every AWS operation observe may call. permissions/observe-policy.json is generated from this.
OPERATIONS: dict[tuple[str, str], str] = {
    ("iam", "generate_service_last_accessed_details"): "iam:GenerateServiceLastAccessedDetails",
    ("iam", "get_service_last_accessed_details"): "iam:GetServiceLastAccessedDetails",
    ("cloudtrail", "lookup_events"): "cloudtrail:LookupEvents",
    ("accessanalyzer", "get_generated_policy"): "access-analyzer:GetGeneratedPolicy",
}

_DENIED_CODES = ("AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation",
                 "UnauthorizedOperation")  # fmt: skip
# CloudTrail event source -> IAM service prefix, where they differ.
_SOURCE_PREFIX = {"monitoring": "cloudwatch", "email": "ses"}
_POLL_ATTEMPTS = 30
LOOKUP_PAGE = 50
# LookupEvents allows two requests per second per Region.
LOOKUP_PAUSE = 0.6


def _call(
    provider: AWSClientProvider, service: str, operation: str, region: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:  # fmt: skip
    if (service, operation) not in OPERATIONS:
        raise RuntimeError(f"{service}.{operation} is not an allow-listed observe operation")
    try:
        result: dict[str, Any] = getattr(provider.client(service, region), operation)(**kwargs)
        return result
    except (BotoCoreError, ClientError) as exc:
        raise translate(exc, f"calling {OPERATIONS[(service, operation)]}") from exc


def permission_manifest() -> dict[str, Any]:
    return read_only_manifest("FmawsObserveReadOnly", OPERATIONS)


def principal_arn(value: str, account: str, partition: str = "aws") -> str:
    """Accept a full ARN or the short forms ``role/name`` and ``user/name``."""
    if value.startswith("arn:"):
        arn = value
    elif value.startswith(("role/", "user/")):
        arn = f"arn:{partition}:iam::{account}:{value}"
    else:
        raise ConfigError(
            f"Invalid principal '{value}'. Use a role or user ARN, 'role/NAME' or 'user/NAME'."
        )
    kind = arn.split(":", 5)[-1].split("/")[0]
    if ":iam::" not in arn or kind not in ("role", "user"):
        raise ConfigError(f"Principal '{value}' must be an IAM role or IAM user.")
    return arn


@dataclass
class Evidence:
    # Service prefix -> last authenticated. Present only for services the principal can use today.
    services: dict[str, datetime | None] = field(default_factory=dict)
    # Lowercase "service:action" -> last accessed, for actions IAM tracks individually.
    actions: dict[str, datetime | None] = field(default_factory=dict)
    # "service:Action" -> most recent CloudTrail event.
    events: dict[str, datetime] = field(default_factory=dict)
    denied: dict[str, datetime] = field(default_factory=dict)
    # Action patterns of an observed policy (for example from Access Analyzer).
    observed: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def last_accessed(
    provider: AWSClientProvider, arn: str, evidence: Evidence,
    sleep: Callable[[float], None] = time.sleep,
) -> None:  # fmt: skip
    """IAM action last accessed information: two API calls plus a short poll."""
    job = _call(provider, "iam", "generate_service_last_accessed_details", Arn=arn,
                Granularity="ACTION_LEVEL")["JobId"]  # fmt: skip
    for _ in range(_POLL_ATTEMPTS):
        page = _call(provider, "iam", "get_service_last_accessed_details", JobId=job)
        if page.get("JobStatus") != "IN_PROGRESS":
            break
        sleep(1)
    else:
        raise FmawsError("IAM did not finish the last accessed report in time. Retry later.")
    if page.get("JobStatus") == "FAILED":
        raise FmawsError("IAM could not produce last accessed information for this principal.")
    services = list(page.get("ServicesLastAccessed", []))
    while page.get("IsTruncated"):
        page = _call(provider, "iam", "get_service_last_accessed_details", JobId=job,
                     Marker=page["Marker"])  # fmt: skip
        services.extend(page.get("ServicesLastAccessed", []))
    for service in services:
        prefix = service["ServiceNamespace"]
        evidence.services[prefix] = service.get("LastAuthenticated")
        for tracked in service.get("TrackedActionsLastAccessed", []):
            name = f"{prefix}:{tracked['ActionName']}".lower()
            evidence.actions[name] = tracked.get("LastAccessedTime")
    evidence.sources.append("IAM last accessed")


def cloudtrail_events(
    provider: AWSClientProvider, arn: str, evidence: Evidence, start: datetime, end: datetime,
    region: str | None, max_events: int, sleep: Callable[[float], None] = time.sleep,
) -> None:  # fmt: skip
    """CloudTrail management events of one Region, paced and capped."""
    name = arn.split("/")[-1]
    is_user = ":user/" in arn
    kwargs: dict[str, Any] = {"StartTime": start, "EndTime": end, "MaxResults": LOOKUP_PAGE}
    if is_user:
        # Roles cannot be filtered server-side: their events carry the session name.
        kwargs["LookupAttributes"] = [{"AttributeKey": "Username", "AttributeValue": name}]
    scanned = 0
    token: str | None = None
    while True:
        page = _call(provider, "cloudtrail", "lookup_events", region,
                     **kwargs, **({"NextToken": token} if token else {}))  # fmt: skip
        for event in page.get("Events", []):
            scanned += 1
            try:
                detail = json.loads(event.get("CloudTrailEvent") or "{}")
            except ValueError:
                continue
            identity = detail.get("userIdentity") or {}
            issuer = ((identity.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
            if arn not in (identity.get("arn"), issuer):
                continue
            source = str(detail.get("eventSource", "")).split(".")[0]
            action = f"{_SOURCE_PREFIX.get(source, source)}:{detail.get('eventName', '')}"
            when = event.get("EventTime") or end
            target = (
                evidence.denied if detail.get("errorCode") in _DENIED_CODES else evidence.events
            )
            if action not in target or when > target[action]:
                target[action] = when
        token = page.get("NextToken")
        if not token:
            break
        if scanned >= max_events:
            evidence.notes.append(
                f"CloudTrail lookup stopped after {scanned} events (--max-events). "
                "Older activity in the period was not read."
            )
            break
        sleep(LOOKUP_PAUSE)
    where = region or provider.region or "the default Region"
    evidence.sources.append(f"CloudTrail management events ({where})")
    evidence.notes.append(
        "CloudTrail lookup covers management events of one Region for at most 90 days. Data "
        "events (S3 objects, DynamoDB items, Lambda invocations) are not included."
    )


def _allow_statements(document: Any) -> Iterator[tuple[str, dict[str, Any], list[str]]]:
    """(label, statement, actions) of every Allow statement. The label identifies a statement
    in the report and when removing actions, so it is computed in exactly one place."""
    statements = as_list(document.get("Statement", [])) if isinstance(document, dict) else []
    for index, statement in enumerate(statements):
        if isinstance(statement, dict) and statement.get("Effect") == "Allow":
            actions = [a for a in as_list(statement.get("Action", [])) if isinstance(a, str)]
            yield str(statement.get("Sid") or f"Statement[{index}]"), statement, actions


def _policy_actions(document: Any) -> list[str]:
    return [action for _, _, actions in _allow_statements(document) for action in actions]


def observed_policy(document: Any, evidence: Evidence, label: str) -> None:
    actions = _policy_actions(document)
    if not actions:
        raise ConfigError(f"{label} contains no Allow actions.")
    evidence.observed.extend(actions)
    evidence.sources.append(label)


def access_analyzer_job(provider: AWSClientProvider, job_id: str, evidence: Evidence) -> None:
    """Read the result of an existing policy generation job. fmaws never starts one."""
    result = _call(provider, "accessanalyzer", "get_generated_policy",
                   provider.region or "us-east-1", jobId=job_id)  # fmt: skip
    status = (result.get("jobDetails") or {}).get("status")
    if status != "SUCCEEDED":
        raise FmawsError(f"Access Analyzer policy generation job {job_id} is {status}.")
    generated = (result.get("generatedPolicyResult") or {}).get("generatedPolicies", [])
    for item in generated:
        try:
            document = json.loads(item.get("policy", "{}"))
        except ValueError as exc:
            raise FmawsError("Access Analyzer returned a policy that is not valid JSON.") from exc
        observed_policy(document, evidence, f"Access Analyzer job {job_id}")


def _allowed(patterns: list[str], action: str) -> bool:
    return any(action_allows(pattern, action) for pattern in patterns)


def _day(moment: datetime | None) -> str | None:
    return moment.date().isoformat() if moment else None


def classify(document: dict[str, Any], evidence: Evidence, cutoff: datetime) -> list[Observation]:
    """One observation per candidate action, then the activity the candidate does not cover."""
    candidate = _policy_actions(document)
    observations = [
        _classify_action(action, label, evidence, cutoff)
        for label, _, actions in _allow_statements(document)
        for action in actions
    ]

    def missing(action: str, when: datetime | None, source: str, detail: str) -> None:
        if not _allowed(candidate, action) and not any(
            o.status == MISSING and o.action.lower() == action.lower() for o in observations
        ):
            observations.append(
                Observation(
                    action=action,
                    status=MISSING,
                    last_seen=_day(when),
                    source=source,
                    detail=detail,
                )
            )

    for action, when in sorted(evidence.denied.items()):
        missing(action, when, "CloudTrail", "The principal was denied this action in the period.")
    for action, when in sorted(evidence.events.items()):
        missing(action, when, "CloudTrail", "Used in the period, not allowed by the candidate.")
    for action, moment in sorted(evidence.actions.items()):
        if moment and moment >= cutoff:
            missing(action, moment, "IAM last accessed",
                    "Used in the period, not allowed by the candidate.")  # fmt: skip
    for action in sorted(set(evidence.observed)):
        missing(action, None, "observed policy", "In the observed policy, not in the candidate.")
    return observations


def _classify_action(action: str, label: str, evidence: Evidence, cutoff: datetime) -> Observation:
    def result(status: str, when: datetime | None, source: str, detail: str) -> Observation:
        return Observation(action=action, status=status, statement=label, last_seen=_day(when),
                           source=source, detail=detail)  # fmt: skip

    if "*" in action or "?" in action:
        return result(UNKNOWN, None, "", "Wildcard actions cannot be observed individually.")
    key = action.lower()
    prefix = key.split(":")[0]

    event = next((w for a, w in evidence.events.items() if a.lower() == key), None)
    if event:
        return result(USED, event, "CloudTrail", "Seen in CloudTrail in the period.")
    if key in evidence.actions:
        moment = evidence.actions[key]
        if moment and moment >= cutoff:
            return result(USED, moment, "IAM last accessed", "Used in the period.")
    if _allowed(evidence.observed, action):
        return result(USED, None, "observed policy", "Present in the observed policy.")
    if key in evidence.actions:
        moment = evidence.actions[key]
        seen = f"last used {_day(moment)}" if moment else "never used in the tracking period"
        return result(UNUSED, moment, "IAM last accessed",
                      f"IAM tracks this action: {seen}.")  # fmt: skip
    if prefix in evidence.services:
        moment = evidence.services[prefix]
        if moment is None or moment < cutoff:
            seen = f"last used {_day(moment)}" if moment else "never used in the tracking period"
            detail = f"The whole {prefix} service was not used in the period: {seen}."
            return result(UNUSED, moment, "IAM last accessed", detail)
        return result(UNKNOWN, moment, "IAM last accessed",
                      f"The {prefix} service was used, but IAM does not track this action "
                      "individually.")  # fmt: skip
    if evidence.services:
        detail = f"The principal has no access to {prefix} today, so use cannot be observed."
        return result(UNKNOWN, None, "", detail)
    return result(UNKNOWN, None, "", "No evidence source covers this action.")


def recommend(
    document: dict[str, Any],
    observations: list[Observation],
    days: int,
    min_days: int,
    declared: set[str],
) -> dict[str, Any]:
    """The candidate without long-unused, undeclared actions. Marks what it removed.

    ``declared`` holds the labels of statements backed by explicit configuration: those are
    never removed, whatever the evidence says.
    """
    removable: set[tuple[str, str]] = set()
    if days >= min_days:
        for observation in observations:
            if observation.status == UNUSED and observation.statement not in declared:
                observation.removed = True
                removable.add((observation.statement, observation.action))
    trimmed = {
        id(statement): [a for a in actions if (label, a) not in removable]
        for label, statement, actions in _allow_statements(document)
    }
    kept: list[Any] = []
    for statement in as_list(document.get("Statement", [])):
        if id(statement) not in trimmed:
            kept.append(statement)  # not an Allow statement: passed through untouched
        elif trimmed[id(statement)]:
            actions = trimmed[id(statement)]
            kept.append({**statement, "Action": actions[0] if len(actions) == 1 else actions})
    return {**document, "Statement": kept}


def window(days: int, end: datetime) -> datetime:
    return end - timedelta(days=days)
