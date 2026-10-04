"""The generate pipeline: configuration and discovery in, explained candidate policy out."""

import re
from dataclasses import dataclass
from pathlib import Path

from fmaws.aws.session import AWSClientProvider
from fmaws.config.loader import load_config, requirements_from_config
from fmaws.discovery.base import Detection, discover
from fmaws.discovery.merge import merge_requirements, single
from fmaws.errors import FmawsError
from fmaws.models.finding import Severity
from fmaws.models.policy import PolicyDocument
from fmaws.models.report import Report, status
from fmaws.models.requirement import Confidence
from fmaws.policy.arns import REGION_RE, ArnContext
from fmaws.policy.generator import generate_policy
from fmaws.validators.access_analyzer import validate_with_access_analyzer
from fmaws.validators.local import validate_policy_document

_ACCOUNT_RE = re.compile(r"\d{12}")


def _valid(values: list[str], pattern: re.Pattern[str]) -> list[str]:
    """Hints come from project files: anything that is not a plain region or account is dropped."""
    return [v for v in values if pattern.fullmatch(v)]


WILDCARD_SEVERITY = {"info": Severity.INFO, "warning": Severity.MEDIUM, "error": Severity.HIGH}


@dataclass
class GenerateOptions:
    root: Path
    config_path: Path | None = None
    profile: str | None = None
    region: str | None = None
    all_regions: bool = False
    strict: bool = False
    validate: bool = False
    output: Path | None = None


def _ambient_region(provider: AWSClientProvider) -> str | None:
    try:
        return provider.region
    except FmawsError:
        # A broken ambient profile must not stop offline generation.
        return None


def run_generate(options: GenerateOptions) -> tuple[Report, PolicyDocument | None]:
    loaded = load_config(options.root, options.config_path)
    config = loaded.config
    report = Report(command="generate")

    detection = Detection()
    if config.discovery.enabled:
        exclude = [p for p in (options.output, loaded.path) if p is not None]
        detection = discover(
            options.root, config.discovery.paths, config.discovery.detectors, exclude
        )
        report.notes.extend(detection.notes)

    requirements = merge_requirements(requirements_from_config(loaded), detection.requirements)
    if options.strict:
        kept = [r for r in requirements if r.confidence is Confidence.HIGH]
        dropped = len(requirements) - len(kept)
        if dropped:
            report.notes.append(
                f"--strict: {dropped} discovered resource(s) excluded. Only resources declared "
                "in fmaws.yaml are included."
            )
        requirements = kept
    if not requirements:
        report.notes.append(
            "No AWS resources were declared or detected. Create fmaws.yaml and list the "
            "resources the application uses (see docs/configuration.md)."
        )
        return report, None

    profile = options.profile or config.aws.profile
    provider = AWSClientProvider(profile, options.region or config.aws.region)
    online = options.validate or options.profile is not None

    region: str | None = "*"
    if not options.all_regions:
        region = options.region or config.aws.region or single(_valid(detection.regions, REGION_RE))
        region = region or _ambient_region(provider)
    if not region:
        region = "*"
        report.notes.append(
            "Region unknown: ARNs use a region wildcard. Set aws.region in fmaws.yaml or "
            "pass --region."
        )
    account = config.aws.account_id or single(_valid(detection.accounts, _ACCOUNT_RE))
    if not account and online:
        account = provider.identity()["account"]
    ctx = ArnContext(partition=config.aws.partition, region=region, account=account or "*")
    report.context = {"partition": ctx.partition, "region": ctx.region, "account": ctx.account}

    policy = generate_policy(requirements, ctx, config.policy.include_conditions)
    report.policy = policy.to_iam()
    report.statements = list(policy.statements)
    report.unconfirmed = [r for r in requirements if not r.intent_confirmed]

    local = validate_policy_document(
        report.policy, WILDCARD_SEVERITY[config.policy.wildcard_action_threshold]
    )
    report.local_validation = status(local)
    report.findings.extend(local)
    if options.validate:
        remote = validate_with_access_analyzer(provider, policy.to_json())
        report.aws_validation = status(remote)
        report.findings.extend(remote)
    return report, policy


def exit_code(report: Report, strict: bool = False) -> int:
    if report.errors or (strict and report.warnings):
        return 1
    return 0
