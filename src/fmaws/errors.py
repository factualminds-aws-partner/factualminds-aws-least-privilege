"""Exceptions that map directly to CLI exit codes."""


class FmawsError(Exception):
    """Configuration or runtime error (exit code 2)."""

    exit_code = 2


class ConfigError(FmawsError):
    """Invalid configuration or invalid user-supplied input."""


class AwsAuthError(FmawsError):
    """AWS authentication or authorization failure (exit code 3)."""

    exit_code = 3
