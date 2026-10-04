"""Generated policies for realistic projects, pinned so any change in output is reviewed."""

import json
import os

import pytest

from fmaws.pipeline import GenerateOptions, run_generate
from fmaws.policy import catalog
from tests.conftest import PROJECTS, REPO

GOLDEN = REPO / "tests" / "golden"


def generated(project):
    report, policy = run_generate(GenerateOptions(root=project))
    assert policy is not None
    return report, policy


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: p.name)
def test_policy_matches_golden(project):
    _, policy = generated(project)
    golden = GOLDEN / f"{project.name}.json"
    if os.environ.get("UPDATE_GOLDEN"):
        golden.write_text(policy.to_json())
    assert policy.to_json() == golden.read_text()


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: p.name)
def test_generation_is_deterministic(project):
    assert generated(project)[1].to_json() == generated(project)[1].to_json()


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: p.name)
def test_no_wildcard_escalation(project):
    report, policy = generated(project)
    star_only = catalog.star_actions()
    for statement in policy.to_iam()["Statement"]:
        actions = (
            statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        )
        assert all("*" not in action for action in actions)
        if statement["Resource"] == "*":
            assert all(action in star_only for action in actions)
    assert report.errors == 0
    assert report.local_validation == "PASS"


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: p.name)
def test_every_statement_has_reason_source_and_confidence(project):
    report, _ = generated(project)
    for statement in report.statements:
        assert statement.explanations
        for explanation in statement.explanations:
            assert explanation.reason and explanation.source and explanation.confidence


def test_planted_secrets_never_reach_policy_or_report():
    from fmaws.reporters.base import render

    for name in ("ai-agent", "order-pipeline"):
        report, policy = generated(REPO / "tests" / "fixtures" / name)
        outputs = [policy.to_json()] + [render(report, f) for f in ("console", "json", "markdown")]
        report.show_explanations = True
        outputs.append(render(report, "console"))
        for output in outputs:
            for secret in ("wJalr", "sk-test", "sk_live", "correct-horse"):
                assert secret not in output
        json.loads(outputs[2])
