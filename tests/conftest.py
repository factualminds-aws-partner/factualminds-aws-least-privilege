from pathlib import Path

import pytest

from fmaws.config import loader

REPO = Path(__file__).resolve().parent.parent
PROJECTS = sorted(
    [p for p in (REPO / "tests" / "fixtures").iterdir() if p.is_dir()]
    + [REPO / "examples" / "ecommerce-ai-agent"]
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    """No ambient AWS configuration, no user-level fmaws configuration, no network metadata."""
    for name in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    monkeypatch.setattr(loader, "USER_CONFIG", tmp_path / "no-user-config.yaml")
