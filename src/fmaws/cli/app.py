"""fmaws command line interface.

Every command is read-only with respect to AWS. Exit codes: 0 success, 1 findings exceed the
threshold, 2 configuration or runtime error, 3 AWS authentication or authorization error.
"""

import functools
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer

from fmaws import __version__
from fmaws import observe as observation
from fmaws.audit.base import AuditContext, apply_config, resolve_regions, run_audit
from fmaws.audit.scoring import scores
from fmaws.aws.session import AWSClientProvider
from fmaws.config.loader import load_config
from fmaws.config.schema import Config
from fmaws.errors import AwsAuthError, ConfigError, FmawsError
from fmaws.models.finding import Severity
from fmaws.models.policy import Explanation, Statement
from fmaws.models.report import COMPLETED, Report, status
from fmaws.models.requirement import Confidence
from fmaws.pipeline import WILDCARD_SEVERITY, GenerateOptions, exit_code, run_generate
from fmaws.policy import catalog
from fmaws.reporters.base import render
from fmaws.utils.redact import mask_account, redact
from fmaws.validators.access_analyzer import FALLBACK_REGION, validate_with_access_analyzer
from fmaws.validators.local import as_list, load_policy_file, validate_policy_document

app = typer.Typer(
    name="fmaws",
    help="FactualMinds AWS Least Privilege Advisor. Read-only: it never changes your AWS account.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


class Format(StrEnum):
    console = "console"
    json = "json"
    markdown = "markdown"
    sarif = "sarif"


class FailOn(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


ProfileOpt = Annotated[str | None, typer.Option("--profile", help="AWS profile name.")]
RegionOpt = Annotated[str | None, typer.Option("--region", help="AWS region.")]
ConfigOpt = Annotated[Path | None, typer.Option("--config", help="Path to fmaws.yaml.")]
FormatOpt = Annotated[Format, typer.Option("--format", help="Report format.")]


def emit(text: str) -> None:
    typer.echo(redact(text), nl=not text.endswith("\n"))


def _provider(settings: Config, profile: str | None, region: str | None) -> AWSClientProvider:
    return AWSClientProvider(profile or settings.aws.profile, region or settings.aws.region)


def _require_file(path: Path) -> None:
    if not path.is_file():
        raise FmawsError(f"Policy file {path} does not exist.")


def _write(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise FmawsError(f"Cannot write {path}: {exc.strerror}.") from exc


def handle_errors(command: Callable[..., None]) -> Callable[..., None]:
    """Turn fmaws errors into a clear message and the documented exit code."""

    @functools.wraps(command)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        try:
            command(*args, **kwargs)
        except FmawsError as exc:
            typer.echo(redact(f"Error: {exc}"), err=True)
            raise typer.Exit(exc.exit_code) from exc

    return wrapper


def _version(value: bool) -> None:
    if value:
        typer.echo(f"fmaws {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show the version."),
    ] = False,
) -> None:
    pass


@app.command()
@handle_errors
def generate(
    profile: ProfileOpt = None,
    region: RegionOpt = None,
    all_regions: Annotated[
        bool, typer.Option("--all-regions", help="Do not pin ARNs to one region.")
    ] = False,
    config: ConfigOpt = None,
    output: Annotated[
        Path, typer.Option("--output", help="Where to write the policy JSON.")
    ] = Path("generated-policy.json"),
    fmt: FormatOpt = Format.console,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Only declared resources; warnings fail the run."),
    ] = False,
    explain: Annotated[
        bool, typer.Option("--explain", help="Show why each statement exists.")
    ] = False,
    validate: Annotated[
        bool, typer.Option("--validate", help="Also validate with IAM Access Analyzer.")
    ] = False,
) -> None:
    """Generate a candidate least-privilege IAM policy for the project in the current directory."""
    options = GenerateOptions(
        root=Path.cwd(), config_path=config, profile=profile, region=region,
        all_regions=all_regions, strict=strict, validate=validate, output=output.resolve(),
    )  # fmt: skip
    report, policy = run_generate(options)
    report.show_explanations = explain
    if policy is not None:
        _write(output, redact(policy.to_json()))
        report.policy_path = str(output)
    emit(render(report, fmt))
    raise typer.Exit(exit_code(report, strict))


def _explain_file(path: Path) -> Report:
    """Explain an existing policy from what the service catalog knows about each action."""
    document, findings = load_policy_file(path)
    report = Report(command="explain", policy_path=str(path), show_explanations=True)
    report.findings = findings or validate_policy_document(document)
    report.local_validation = status(report.findings)
    if findings or not isinstance(document, dict):
        return report

    known: dict[str, str] = {}
    for definition in catalog.CATALOG.values():
        for intent, actions in definition.intents.items():
            for action in actions:
                known.setdefault(action, f"{intent} access to a {definition.title}")
    star = catalog.star_actions()
    for index, item in enumerate(as_list(document.get("Statement", []))):
        if not isinstance(item, dict) or "Action" not in item or "Resource" not in item:
            continue
        names, resources = as_list(item["Action"]), as_list(item["Resource"])
        explanations = []
        for action in map(str, names):
            if action in star:
                reason = f'{action}: requires Resource "*". {star[action]}'
            elif action in known:
                reason = f"{action}: {known[action]}"
            elif action.startswith("s3:"):
                reason = f"{action}: S3 access, see docs/s3-least-privilege.md"
            else:
                reason = f"{action}: not in the fmaws service catalog"
            explanations.append(
                Explanation(
                    reason=f"{item.get('Effect', 'Allow')} {reason}",
                    source=f"{path.name}:Statement[{index}]",
                    confidence=Confidence.HIGH,
                )
            )
        report.statements.append(
            Statement(
                sid=str(item.get("Sid", "")),
                actions=tuple(map(str, names)),
                resources=tuple(map(str, resources)),
                conditions=item.get("Condition") if isinstance(item.get("Condition"), dict) else {},
                explanations=tuple(explanations),
            )
        )
    return report


@app.command()
@handle_errors
def explain(
    policy_file: Annotated[
        Path | None,
        typer.Argument(
            help="Policy to explain. Omit to explain the policy generate would produce."
        ),
    ] = None,
    profile: ProfileOpt = None,
    region: RegionOpt = None,
    config: ConfigOpt = None,
    fmt: FormatOpt = Format.console,
) -> None:
    """Explain why each permission exists: reason, source and confidence."""
    if policy_file is not None:
        _require_file(policy_file)
        report = _explain_file(policy_file)
    else:
        options = GenerateOptions(
            root=Path.cwd(), config_path=config, profile=profile, region=region
        )
        report, _ = run_generate(options)
        report.command = "explain"
    report.show_explanations = True
    emit(render(report, fmt))


@app.command()
@handle_errors
def validate(
    policy_file: Annotated[Path, typer.Argument(help="IAM policy JSON file.")],
    local_only: Annotated[
        bool, typer.Option("--local-only", help="Skip IAM Access Analyzer (no AWS calls).")
    ] = False,
    profile: ProfileOpt = None,
    region: RegionOpt = None,
    config: ConfigOpt = None,
    fmt: FormatOpt = Format.console,
) -> None:
    """Validate an IAM policy locally and with IAM Access Analyzer."""
    _require_file(policy_file)
    settings = load_config(Path.cwd(), config).config
    report = Report(command="validate", policy_path=str(policy_file))
    document, findings = load_policy_file(policy_file)
    if not findings:
        findings = validate_policy_document(
            document, WILDCARD_SEVERITY[settings.policy.wildcard_action_threshold]
        )
    report.findings = list(findings)
    report.local_validation = status(findings)

    structurally_valid = not any(
        f.id in ("POLICY_INVALID_JSON", "POLICY_TOO_LARGE") for f in findings
    )
    if local_only:
        report.aws_validation = "SKIPPED (--local-only)"
    elif not structurally_valid:
        report.aws_validation = "SKIPPED (policy could not be parsed)"
    else:
        provider = _provider(settings, profile, region)
        try:
            remote = validate_with_access_analyzer(
                provider, policy_file.read_text(encoding="utf-8")
            )
        except AwsAuthError as exc:
            # Local results are still worth showing before the auth failure ends the run.
            report.aws_validation = "FAILED TO RUN"
            emit(render(report, fmt))
            raise AwsAuthError(f"{exc} Use --local-only to validate without AWS.") from exc
        report.aws_validation = status(remote)
        report.findings.extend(remote)
    emit(render(report, fmt))
    raise typer.Exit(exit_code(report))


@app.command()
@handle_errors
def doctor(profile: ProfileOpt = None, region: RegionOpt = None) -> None:
    """Check AWS authentication, identity, region and the permissions fmaws uses."""
    settings = load_config(Path.cwd()).config
    provider = _provider(settings, profile, region)
    lines: list[str] = []

    def check(label: str, state: str, detail: str) -> None:
        lines.append(f"{state:<5} {label}: {detail}")

    check("Profile", "OK", provider.profile or "default credential chain")
    failure: FmawsError | None = None
    if not provider.has_credentials():
        check("Credentials", "FAIL", "none found in the credential provider chain")
        failure = AwsAuthError(
            "No AWS credentials found. Configure a profile (aws configure sso), "
            "set AWS_PROFILE, or pass --profile."
        )
    else:
        check("Credentials", "OK", "resolved through the standard provider chain")
        try:
            identity = provider.identity()
            check("Identity", "OK", identity["arn"].replace(
                identity["account"], mask_account(identity["account"])))  # fmt: skip
            check("Account", "OK", mask_account(identity["account"]))
        except FmawsError as exc:
            check("Identity", "FAIL", "sts:GetCallerIdentity failed")
            failure = exc

    if provider.region:
        check("Region", "OK", provider.region)
    else:
        check("Region", "WARN", f"not configured; {FALLBACK_REGION} is used for Access Analyzer")

    if failure is None:
        probe = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",' \
                '"Action":"s3:GetObject","Resource":"arn:aws:s3:::example-bucket/*"}]}'  # fmt: skip
        try:
            validate_with_access_analyzer(provider, probe)
            check("access-analyzer:ValidatePolicy", "OK", "fmaws validate can use Access Analyzer")
        except AwsAuthError:
            check("access-analyzer:ValidatePolicy", "WARN",
                  "not allowed; use --local-only or grant the permission")  # fmt: skip
        except FmawsError as exc:
            check("access-analyzer:ValidatePolicy", "WARN", str(exc))

    emit("\n".join(lines) + "\n")
    if failure is not None:
        raise failure
    if sys.stdout.isatty():
        typer.echo("\nNext: fmaws generate")


@app.command()
@handle_errors
def audit(
    profile: ProfileOpt = None,
    region: RegionOpt = None,
    all_regions: Annotated[
        bool, typer.Option("--all-regions", help="Audit every Region enabled for the account.")
    ] = False,
    config: ConfigOpt = None,
    fmt: FormatOpt = Format.console,
    fail_on: Annotated[
        FailOn | None,
        typer.Option("--fail-on", help="Exit 1 if a finding has this severity or higher."),
    ] = None,
    allow_partial: Annotated[
        bool,
        typer.Option(
            "--allow-partial",
            help="With a fail-on threshold, accept an audit where some analyzers could not run.",
        ),
    ] = False,
) -> None:
    """Read-only security audit of the AWS account. Nothing is changed."""
    settings = load_config(Path.cwd(), config).config
    provider = _provider(settings, profile, region)
    identity = provider.identity()
    regions = resolve_regions(provider, settings, region, all_regions)
    ctx = AuditContext(provider, identity["account"], regions, settings)

    raw, statuses = run_audit(ctx)
    findings, ignored = apply_config(raw, settings)
    report = Report(
        command="audit",
        findings=findings,
        analyzers=statuses,
        scores=scores(findings),
        ignored=ignored,
        context={
            "account": identity["account"],
            "region": ", ".join(regions) if len(regions) <= 3 else f"{len(regions)} Regions",
        },
    )
    emit(render(report, fmt))

    ran = [s for s in statuses if s.status == COMPLETED]
    if not ran:
        raise AwsAuthError(
            "No analyzer could run. Attach permissions/audit-readonly-policy.json "
            "(see docs/required-aws-permissions.md)."
        )
    names = [fail_on.value] if fail_on else settings.audit_fail_on
    threshold = min((Severity(n.upper()) for n in names), key=lambda s: s.rank, default=None)
    if threshold is None:
        return
    if any(f.severity.rank >= threshold.rank for f in findings):
        raise typer.Exit(1)
    incomplete = [s.name for s in statuses if s.incomplete]
    if incomplete and not allow_partial:
        # A gate must not pass on an audit that did not look everywhere.
        raise FmawsError(
            f"The audit is incomplete ({', '.join(incomplete)}), so the --fail-on gate cannot "
            "pass. Grant the missing permissions or use --allow-partial."
        )


@app.command()
@handle_errors
def observe(
    principal: Annotated[
        str | None,
        typer.Option("--principal", help="Role or user the application runs as (ARN, role/NAME)."),
    ] = None,
    days: Annotated[
        int | None, typer.Option("--days", min=1, max=400, help="Observation period in days.")
    ] = None,
    policy_file: Annotated[
        Path | None,
        typer.Option("--policy", help="Candidate policy. Default: the policy generate produces."),
    ] = None,
    cloudtrail: Annotated[
        bool, typer.Option("--cloudtrail", help="Also read CloudTrail management events.")
    ] = False,
    max_events: Annotated[
        int | None, typer.Option("--max-events", min=50, help="Cap on CloudTrail events read.")
    ] = None,
    observed_policy: Annotated[
        Path | None,
        typer.Option("--observed-policy", help="A policy describing observed activity."),
    ] = None,
    access_analyzer_job: Annotated[
        str | None,
        typer.Option(
            "--access-analyzer-job", help="Finished Access Analyzer policy generation job."
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write the recommended policy here.")
    ] = None,
    profile: ProfileOpt = None,
    region: RegionOpt = None,
    config: ConfigOpt = None,
    fmt: FormatOpt = Format.console,
) -> None:
    """Compare a candidate policy with what the principal actually did. Read-only."""
    settings = load_config(Path.cwd(), config).config
    target = principal or settings.observe.principal
    if not target:
        raise ConfigError(
            "Which principal should be observed? Pass --principal with the ARN of the role "
            "or user the application runs as, or set observe.principal in fmaws.yaml."
        )
    period = days or settings.observe.days

    declared: set[str] = set()
    notes: list[str] = []
    if policy_file is not None:
        _require_file(policy_file)
        candidate, problems = load_policy_file(policy_file)
        if problems or not isinstance(candidate, dict):
            raise ConfigError(f"{policy_file} is not a readable IAM policy.")
    else:
        options = GenerateOptions(
            root=Path.cwd(), config_path=config, profile=profile, region=region
        )
        generated, policy = run_generate(options)
        if policy is None:
            raise ConfigError(
                "There is no candidate policy to compare: nothing was declared or detected. "
                "Create fmaws.yaml or pass --policy."
            )
        candidate = policy.to_iam()
        # A statement merged from declared and discovered resources counts as declared: nothing
        # backed by fmaws.yaml may be removed.
        declared = {
            s.sid
            for s in policy.statements
            if any(e.confidence is Confidence.HIGH for e in s.explanations)
        }
        notes.extend(generated.notes)

    provider = _provider(settings, profile, region)
    identity = provider.identity()
    arn = observation.principal_arn(target, identity["account"], settings.aws.partition)
    evidence = observation.Evidence()
    observation.last_accessed(provider, arn, evidence)
    end = datetime.now(UTC)
    start = observation.window(period, end)
    if cloudtrail or settings.observe.cloudtrail:
        lookup_start = observation.window(min(period, 90), end)
        observation.cloudtrail_events(
            provider, arn, evidence, lookup_start, end, region or settings.aws.region,
            max_events or settings.observe.max_events,
        )  # fmt: skip
    if observed_policy is not None:
        _require_file(observed_policy)
        document, problems = load_policy_file(observed_policy)
        if problems:
            raise ConfigError(f"{observed_policy} is not a readable IAM policy.")
        observation.observed_policy(document, evidence, f"observed policy {observed_policy.name}")
    if access_analyzer_job:
        observation.access_analyzer_job(provider, access_analyzer_job, evidence)

    observations = observation.classify(candidate, evidence, start)
    minimum = settings.observe.min_days_for_removal
    recommended = observation.recommend(candidate, observations, period, minimum, declared)
    if period < minimum:
        notes.append(
            f"The period is shorter than {minimum} days (observe.min_days_for_removal), so the "
            "recommended policy keeps every permission of the candidate."
        )
    if declared:
        notes.append("Permissions declared in fmaws.yaml are never removed by observation.")
    report = Report(
        command="observe",
        observations=observations,
        notes=[*evidence.notes, *notes],
        context={
            "account": identity["account"],
            "region": provider.region or "not set",
            "principal": arn,
            "days": str(period),
            "sources": ", ".join(evidence.sources),
        },
    )
    if output is not None:
        _write(output, redact(json.dumps(recommended, indent=2) + "\n"))
        report.policy_path = str(output)
    emit(render(report, fmt))
