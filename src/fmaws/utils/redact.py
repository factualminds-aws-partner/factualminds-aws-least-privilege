"""Last line of defense against credentials reaching any output."""

import re

_PATTERNS = [
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"), "[REDACTED-ACCESS-KEY-ID]"),
    (
        re.compile(
            r"(?i)(aws_secret_access_key|aws_session_token|password|passwd|secret_key|api_key|"
            r"apikey|private_key|client_secret)(\"?\s*[=:]\s*\"?)[^\s\"',}]+"
        ),
        r"\1\2[REDACTED]",
    ),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def mask_account(account: str) -> str:
    """Show only the last four digits of an account ID."""
    return f"{'*' * 8}{account[-4:]}" if re.fullmatch(r"\d{12}", account) else account
