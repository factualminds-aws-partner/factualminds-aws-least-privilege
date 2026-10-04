# Architecture

## Data flow of `fmaws generate`

```
fmaws.yaml ──► config/loader ──┐
                               ├─► discovery/merge ─► policy/generator ─► policy/optimizer
project files ─► discovery ────┘        │                  │   │                 │
                                        │              catalog  s3 engine        ▼
                                        ▼                                  PolicyDocument
                              ResourceRequirement                               │
                                                        validators/local ◄──────┤
                                             validators/access_analyzer ◄───────┤ (--validate)
                                                                                ▼
                                                                    Report ─► reporters
```

1. `config/loader.py` reads `fmaws.yaml` (layered over `~/.config/fmaws/config.yaml`) and turns
   declared resources into `ResourceRequirement` objects with HIGH confidence.
2. `discovery/base.py` walks the project (`discovery/walker.py`) and runs every registered
   detector. Each detector returns requirements with MEDIUM or LOW confidence, plus notes.
3. `discovery/merge.py` combines both lists. Declared resources win; evidence for the same
   discovered resource is folded together.
4. `policy/generator.py` turns requirements into statements: S3 through the dedicated engine in
   `policy/s3.py`, everything else through the declarative catalog in `policy/catalog.py`.
5. `policy/optimizer.py` minimizes without broadening and assigns stable `Sid`s.
6. `validators/local.py` always runs. `validators/access_analyzer.py` runs with `--validate`.
7. `reporters/` renders the `Report` as console text, JSON, Markdown or SARIF. The CLI passes all
   output through `utils/redact.py`.

`pipeline.py` wires these steps; `cli/app.py` only parses options, calls the pipeline and maps
results to exit codes.

## Package layout

| Package | Responsibility |
|---|---|
| `fmaws.cli` | Typer commands, exit code mapping |
| `fmaws.config` | `fmaws.yaml` schema and loading |
| `fmaws.discovery` | File walker, detectors, requirement merging |
| `fmaws.policy` | Service catalog, S3 engine, ARN helpers, generator, optimizer |
| `fmaws.validators` | Local validation, IAM Access Analyzer validation |
| `fmaws.audit` | Account audit: allow-listed AWS access, analyzers, rule catalog, scoring |
| `fmaws.aws` | `AWSClientProvider`: session, cached clients, error translation |
| `fmaws.models` | `ResourceRequirement`, `Statement`, `PolicyDocument`, `Finding`, `Report` |
| `fmaws.reporters` | Console, JSON, Markdown |
| `fmaws.utils` | Redaction, text helpers |

## Extension points

**A new AWS service** is one `ServiceDefinition` registered in `policy/catalog.py`:

```python
register(
    ServiceDefinition(
        service="sqs",
        title="SQS queue",
        config_key="queue",
        arn_template="arn:{partition}:sqs:{region}:{account}:{name}",
        intents={"send": ("sqs:SendMessage",), ...},
        default_intents=("read",),
        star_actions={"sqs:ListQueues": "AWS does not support resource-level permissions ..."},
    )
)
```

The definition declares the resource ARN, the explicit actions behind each intent, which
intents are destructive, which actions only work with `Resource: "*"` and why, additional
resources (DynamoDB indexes) and companion KMS permissions. The generator, the local validator
and `fmaws explain` pick it up without further changes.

**A new detector** is a class with `name`, `matches(path)` and `detect(relative_path, text)`
passed to `discovery.base.register()`.

**A new audit analyzer** is a class with `name`, `regional` and `run(ctx, region)` passed to
`audit.base.register()`. It reads AWS through `ctx.call` / `ctx.pages` / `ctx.optional`, which
only accept operations on the allow-list, and builds findings with `audit.findings.make()` from
a rule in `RULES`. The runner gives every analyzer its own outcome (completed, skipped or
failed with a reason), so a new analyzer cannot break the others.

**A new report format** is a function decorated with `@register("name")` in `fmaws.reporters`.

## Confidence

| Confidence | Source |
|---|---|
| HIGH | Declared in `fmaws.yaml` |
| MEDIUM | Literal ARN, queue URL or resource name in project files, or an AWS SDK call |
| LOW | Resource defined in infrastructure-as-code, usage unknown |

A statement reports the weakest confidence among the evidence behind it.

## Determinism

Requirements, actions, resources, condition values and statements are sorted. `Sid`s are a
hash of the statement content. No timestamps are written. The same project produces the same
bytes, which the golden tests enforce.
