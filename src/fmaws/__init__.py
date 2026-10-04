"""FactualMinds AWS Least Privilege Advisor."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("factualminds-aws-least-privilege")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0.0.0"
