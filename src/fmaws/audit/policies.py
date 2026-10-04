"""Helpers for reading resource and trust policies returned by AWS.

The rule throughout: a statement is treated as restricted only when that can be shown.
Anything fmaws cannot evaluate counts as not restricting.
"""

import ipaddress
import json
import re
from typing import Any

from fmaws.validators.local import action_allows, as_list, condition_values, trivial_condition

# Condition keys that tie a wildcard principal to a network, an organization or an account.
# AWS itself treats a policy with a fixed value for one of these as not public.
_RESTRICTING_KEYS = {
    "aws:sourceip", "aws:sourcevpce", "aws:sourcevpc", "aws:principalorgid",
    "aws:principalorgpaths", "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner",
    "aws:principalaccount", "aws:principalarn", "s3:dataaccesspointaccount",
    "kms:calleraccount", "sts:externalid",
}  # fmt: skip
# kms:ViaService is deliberately absent: it pins the AWS service a request comes through, and
# principals of any account can call through that service.
# Operators that can pin a value. Negated and IfExists forms do not: the first excludes instead
# of restricting, the second is true whenever the key is absent.
_EXACT_OPERATORS = {"stringequals", "stringequalsignorecase"}
_PATTERN_OPERATORS = {"stringlike", "arnequals", "arnlike"}
_IP_OPERATORS = {"ipaddress"}
_ACCOUNT_KEYS = {"aws:principalaccount", "aws:principalarn", "kms:calleraccount"}
# All ranges of a condition together may cover at most this many addresses (a /8 or a /16).
# Beyond that the "restriction" is the internet for practical purposes.
_MAX_ADDRESSES = {4: 2**24, 6: 2**112}


def account_of(value: str) -> str | None:
    """The account a principal or ARN pattern is bound to.

    Only a bare 12-digit ID or the account field of an ARN counts. Digits elsewhere, such as
    in a role name, say nothing about the account.
    """
    if re.fullmatch(r"\d{12}", value):
        return value
    fields = value.split(":")
    if len(fields) >= 6 and fields[0] == "arn" and re.fullmatch(r"\d{12}", fields[4]):
        return fields[4]
    return None


class UnreadablePolicy(ValueError):
    """The policy could not be parsed unambiguously, so nothing can be concluded from it."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise UnreadablePolicy("duplicate keys")
    return dict(pairs)


def parse(document: Any) -> dict[str, Any]:
    """A policy as a dict, whether AWS returned it as JSON text or already decoded.

    A missing policy is an empty dict. A policy that is present but cannot be read, or that
    JSON parsers could read in more than one way, raises instead of looking empty.
    """
    if document is None or document == "":
        return {}
    if isinstance(document, str):
        try:
            document = json.loads(document, object_pairs_hook=_no_duplicate_keys)
        except (ValueError, RecursionError) as exc:
            raise UnreadablePolicy(str(exc)) from exc
    if not isinstance(document, dict):
        raise UnreadablePolicy("not a JSON object")
    return document


def allow_statements(document: Any) -> list[dict[str, Any]]:
    statements = as_list(parse(document).get("Statement", []))
    if any(not isinstance(s, dict) for s in statements):
        raise UnreadablePolicy("a statement is not a JSON object")
    return [s for s in statements if s.get("Effect") == "Allow"]


def aws_principals(statement: dict[str, Any]) -> list[str]:
    principal = statement.get("Principal")
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        return [str(v) for v in as_list(principal.get("AWS", []))]
    return []


def federated_principals(statement: dict[str, Any]) -> list[str]:
    principal = statement.get("Principal")
    if isinstance(principal, dict):
        return [str(v) for v in as_list(principal.get("Federated", []))]
    return []


def is_public(statement: dict[str, Any]) -> bool:
    """Any principal: ``"*"`` in any form, or everyone except a few (``NotPrincipal``)."""
    if "NotPrincipal" in statement:
        return True
    principal = statement.get("Principal")
    if principal == "*" or (isinstance(principal, list) and "*" in principal):
        return True
    return isinstance(principal, dict) and any("*" in as_list(v) for v in principal.values())


def condition(statement: dict[str, Any]) -> dict[str, Any]:
    value = statement.get("Condition")
    return value if isinstance(value, dict) else {}


def is_conditioned(statement: dict[str, Any]) -> bool:
    """Has a condition that can evaluate to false."""
    value = condition(statement)
    return bool(value) and not trivial_condition(value)


def _operator(operator: str) -> str | None:
    """The base operator when it can restrict, else None.

    ``ForAllValues:`` is true for a request without the key, so it restricts nothing.
    """
    prefix, _, base = operator.lower().rpartition(":")
    if prefix not in ("", "foranyvalue"):
        return None
    known = _EXACT_OPERATORS | _PATTERN_OPERATORS | _IP_OPERATORS
    return base if base in known else None


def _pins(operator: str, value: Any) -> bool:
    """Does this single value narrow the caller to something specific?"""
    if not isinstance(value, str) or not value:
        return False
    if "*" not in value and "?" not in value:
        return True
    if operator in _EXACT_OPERATORS:
        return True  # wildcards are literal characters under an exact operator
    # A pattern still restricts when it names an account ("arn:aws:iam::111122223333:role/*").
    return account_of(value) is not None


def _ranges_are_narrow(values: list[Any]) -> bool:
    """IP conditions are judged as a whole: many small ranges can add up to everything."""
    try:
        networks = [ipaddress.ip_network(v, strict=False) for v in values]
    except (ValueError, TypeError):
        return False
    for version, limit in _MAX_ADDRESSES.items():
        same = [n for n in networks if n.version == version]
        merged = ipaddress.collapse_addresses(same)  # type: ignore[type-var]
        if sum(n.num_addresses for n in merged) > limit:
            return False
    return bool(networks)


def _restrictions(statement: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    """(key, values) of every condition entry in which every value pins the caller."""
    found = []
    for operator, key, values in condition_values(condition(statement)):
        base = _operator(operator)
        if not base or not values:
            continue
        if base in _IP_OPERATORS:
            pinned = _ranges_are_narrow(values)
        else:
            pinned = all(_pins(base, v) for v in values)
        if pinned:
            found.append((key.lower(), values))
    return found


def is_restricted(statement: dict[str, Any]) -> bool:
    """True when a condition pins the caller to a network, organization, account or resource."""
    return any(key in _RESTRICTING_KEYS for key, _ in _restrictions(statement))


def _specific_subject(value: Any, operator: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if operator in _EXACT_OPERATORS:
        return True
    literal = re.split(r"[*?]", value, maxsplit=1)[0]
    # "repo:*" or "repo:acme*" match other owners' repositories: the owner must be complete.
    if literal.startswith("repo:"):
        return "/" in literal
    return len(literal) >= 8


def pins_subject(statement: dict[str, Any]) -> bool:
    """An OIDC trust statement whose ``sub`` claim names a specific repository or workload."""
    for operator, key, values in condition_values(condition(statement)):
        base = _operator(operator)
        if not base or base in _IP_OPERATORS or not key.lower().endswith(":sub") or not values:
            continue
        if all(_specific_subject(v, base) for v in values):
            return True
    return False


def external_accounts(statement: dict[str, Any], own: str, trusted: set[str]) -> set[str]:
    """Other accounts the statement reaches, named as principals or pinned by a condition."""
    candidates = list(aws_principals(statement))
    for key, values in _restrictions(statement):
        if key in _ACCOUNT_KEYS:
            candidates += [v for v in values if isinstance(v, str)]
    accounts: set[str] = set()
    for candidate in candidates:
        account = account_of(candidate)
        if account and account != own and account not in trusted:
            accounts.add(account)
    return accounts


def allows(statement: dict[str, Any], *actions: str) -> bool:
    """Does the statement allow at least one of ``actions``?"""
    if "NotAction" in statement:
        excluded = [a for a in as_list(statement["NotAction"]) if isinstance(a, str)]
        return any(not any(action_allows(e, action) for e in excluded) for action in actions)
    granted = [a for a in as_list(statement.get("Action", [])) if isinstance(a, str)]
    return any(action_allows(g, action) for g in granted for action in actions)


def resources(statement: dict[str, Any]) -> list[str]:
    if "NotResource" in statement:
        return ["*"]
    return [r for r in as_list(statement.get("Resource", [])) if isinstance(r, str)]
