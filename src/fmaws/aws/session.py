"""AWS access through the standard credential provider chain. No custom credential storage."""

from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    PartialCredentialsError,
    ProfileNotFound,
    SSOError,
    TokenRetrievalError,
)

from fmaws import __version__
from fmaws.errors import AwsAuthError, FmawsError

_AUTH_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure",
    "ExpiredToken", "ExpiredTokenException", "RequestExpired", "InvalidClientTokenId",
    "UnrecognizedClientException", "SignatureDoesNotMatch", "InvalidSignatureException",
}  # fmt: skip
_EXPIRED_CODES = {"ExpiredToken", "ExpiredTokenException", "RequestExpired"}
_THROTTLE_CODES = {"Throttling", "ThrottlingException", "TooManyRequestsException"}


def translate(exc: Exception, doing: str) -> FmawsError:
    """Map a botocore failure to an fmaws error with a next step."""
    if isinstance(exc, ProfileNotFound):
        return AwsAuthError(f"{exc}. Check ~/.aws/config or pass a different --profile.")
    if isinstance(exc, NoCredentialsError | PartialCredentialsError):
        return AwsAuthError(
            f"No usable AWS credentials while {doing}. Configure a profile "
            "(aws configure sso), set AWS_PROFILE, or pass --profile."
        )
    if isinstance(exc, SSOError | TokenRetrievalError):
        return AwsAuthError(
            f"The AWS SSO session is missing or expired while {doing}. Run: aws sso login"
        )
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _EXPIRED_CODES:
            return AwsAuthError(f"AWS credentials expired while {doing}. Refresh them and retry.")
        if code in _AUTH_CODES:
            return AwsAuthError(
                f"AWS denied the request while {doing} ({code}). "
                "See docs/required-aws-permissions.md for the permissions each command needs."
            )
        if code in _THROTTLE_CODES:
            return FmawsError(f"AWS throttled the request while {doing}. Retry in a moment.")
        return FmawsError(f"AWS error while {doing}: {code}.")
    if isinstance(exc, NoRegionError):
        return FmawsError(f"No AWS region configured while {doing}. Pass --region.")
    if isinstance(exc, BotoCoreError):
        return FmawsError(f"Could not reach AWS while {doing}: {type(exc).__name__}.")
    return FmawsError(f"Unexpected error while {doing}: {type(exc).__name__}.")


class AWSClientProvider:
    """One boto3 session per run, with cached clients and cached caller identity."""

    def __init__(self, profile: str | None = None, region: str | None = None) -> None:
        self.profile = profile
        self._region = region
        self._session: Any = None
        self._clients: dict[tuple[str, str | None], Any] = {}
        self._identity: dict[str, str] | None = None

    @property
    def session(self) -> Any:
        if self._session is None:
            try:
                self._session = boto3.Session(profile_name=self.profile, region_name=self._region)
            except BotoCoreError as exc:
                raise translate(exc, "loading the AWS profile") from exc
        return self._session

    @property
    def region(self) -> str | None:
        region: str | None = self.session.region_name
        return region

    def has_credentials(self) -> bool:
        try:
            return self.session.get_credentials() is not None
        except BotoCoreError:
            return False

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region)
        if key not in self._clients:
            config = Config(
                retries={"mode": "adaptive", "max_attempts": 5},
                connect_timeout=5,
                read_timeout=20,
                user_agent_extra=f"fmaws/{__version__}",
            )
            try:
                self._clients[key] = self.session.client(service, region_name=region, config=config)
            except BotoCoreError as exc:
                raise translate(exc, f"creating the {service} client") from exc
        return self._clients[key]

    def identity(self) -> dict[str, str]:
        """``sts:GetCallerIdentity``, called at most once per run."""
        if self._identity is None:
            try:
                response = self.client("sts").get_caller_identity()
            except (BotoCoreError, ClientError) as exc:
                raise translate(exc, "calling sts:GetCallerIdentity") from exc
            self._identity = {"account": response["Account"], "arn": response["Arn"]}
        return self._identity
