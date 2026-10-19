"""Credential redaction helpers shared by logging and request code."""

import logging
import re

# Matches query-string and mapping-style secrets, e.g.:
#   X-Plex-Token=abc, token=abc, 'X-Plex-Token': 'abc', authToken=abc
_SECRET_KEY = r"(?:(?:x-plex-)?token|authtoken|auth_token|pin|password|secret|api[_-]?key)"
_SECRET_RE = re.compile(
    rf"(?i)({_SECRET_KEY}['\"]?\s*[:=]\s*['\"]?)[^&\s,'\"}}]+"
)


def redact_secrets(value) -> str:
    """Return *value* with common credential fields masked.

    Deliberately conservative: only values attached to a known secret key via
    ``=`` or ``:`` are redacted, so ordinary log text is left alone.
    """
    return _SECRET_RE.sub(r"\1[REDACTED]", str(value))


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts credentials, including inside tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_secrets(super().format(record))


class RedactSecretsFilter(logging.Filter):
    """Mask credentials in log messages and formatted arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            redacted = redact_secrets(message)
            if redacted != message:
                record.msg = redacted
                record.args = ()
        except Exception:
            # Never let logging cleanup break application logging.
            pass
        return True


__all__ = ["redact_secrets", "RedactSecretsFilter", "RedactingFormatter"]
