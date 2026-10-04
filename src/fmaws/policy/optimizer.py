"""Policy minimization that never broadens what a statement grants.

Statements are only merged when the result is semantically identical: same resources and
conditions (union of actions) or same actions and conditions (union of resources). Actions are
never collapsed into wildcards.
"""

import hashlib
import json
import re
from collections.abc import Callable, Hashable

from fmaws.models.policy import Conditions, Explanation, Statement
from fmaws.policy.arns import iam_match


def _conditions_key(conditions: Conditions) -> str:
    return json.dumps(conditions, sort_keys=True)


def _service(statement: Statement) -> str:
    return statement.actions[0].split(":")[0]


def _explanations(*groups: tuple[Explanation, ...]) -> tuple[Explanation, ...]:
    unique = {e for group in groups for e in group}
    return tuple(sorted(unique, key=lambda e: (e.source, e.reason)))


def _normalize(statement: Statement) -> Statement:
    resources = set(statement.resources)
    # Only a pattern can cover another resource.
    patterns = [o for o in resources if "*" in o or "?" in o]
    kept = {r for r in resources if not any(o != r and iam_match(o, r) for o in patterns)}
    conditions: Conditions = {
        operator: {key: sorted(set(values)) for key, values in sorted(keys.items())}
        for operator, keys in sorted(statement.conditions.items())
    }
    return statement.model_copy(
        update={
            "actions": tuple(sorted(set(statement.actions))),
            "resources": tuple(sorted(kept)),
            "conditions": conditions,
            "explanations": _explanations(statement.explanations),
        }
    )


def _merge(
    statements: list[Statement], key: Callable[[Statement], Hashable], union: str
) -> list[Statement]:
    merged: dict[Hashable, Statement] = {}
    for statement in statements:
        k = key(statement)
        if k not in merged:
            merged[k] = statement
            continue
        current = merged[k]
        combined = tuple(sorted({*getattr(current, union), *getattr(statement, union)}))
        merged[k] = current.model_copy(
            update={
                union: combined,
                "explanations": _explanations(current.explanations, statement.explanations),
            }
        )
    return list(merged.values())


def _covers(broad: Statement, narrow: Statement) -> bool:
    if broad.conditions and broad.conditions != narrow.conditions:
        return False
    return all(any(iam_match(b, r) for b in broad.resources) for r in narrow.resources)


def _drop_covered(statements: list[Statement]) -> list[Statement]:
    """Remove actions already granted on the same resources by a broader statement."""
    extra: dict[int, tuple[Explanation, ...]] = {}
    kept: dict[int, Statement] = {}
    # Processed in order against the current state: once a statement has given an action up,
    # it no longer counts as covering it, so two statements can never drop the same action.
    actions = [set(s.actions) for s in statements]
    for index, statement in enumerate(statements):
        covering = [
            i
            for i, other in enumerate(statements)
            if i != index and actions[i] and _covers(other, statement)
        ]
        for i in covering:
            actions[index] -= actions[i]
        remaining = actions[index]
        if remaining:
            kept[index] = statement.model_copy(update={"actions": tuple(sorted(remaining))})
        else:
            # The reason this statement existed now explains the statement that covers it.
            extra[covering[0]] = _explanations(extra.get(covering[0], ()), statement.explanations)
    return [
        s.model_copy(update={"explanations": _explanations(s.explanations, extra.get(i, ()))})
        for i, s in kept.items()
    ]


def _sid(statement: Statement) -> str:
    payload = json.dumps(
        [statement.actions, statement.resources, statement.conditions], sort_keys=True
    )
    digest = hashlib.sha256(payload.encode()).hexdigest()[:6]
    service, action = statement.actions[0].split(":")
    return re.sub(r"[^A-Za-z0-9]", "", f"{service.capitalize()}{action}{digest}")


def optimize(statements: list[Statement]) -> list[Statement]:
    result = [_normalize(s) for s in statements if s.actions and s.resources]
    # Each merge can make another one possible, so repeat until nothing changes.
    while True:
        merged = _merge(
            result, lambda s: (_service(s), s.resources, _conditions_key(s.conditions)), "actions"
        )
        merged = _merge(
            merged, lambda s: (_service(s), s.actions, _conditions_key(s.conditions)), "resources"
        )
        merged = [_normalize(s) for s in merged]
        if len(merged) == len(result):
            break
        result = merged
    result = _drop_covered(merged)
    result.sort(key=lambda s: (_service(s), s.resources, s.actions, _conditions_key(s.conditions)))
    return [s.model_copy(update={"sid": _sid(s)}) for s in result]
