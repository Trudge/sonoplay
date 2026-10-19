"""Centralized logging configuration for Sonoplay."""

import logging
import sys

from redaction import RedactSecretsFilter, RedactingFormatter, redact_secrets


def configure_logging(level: str = "INFO") -> None:
    """Configure root logger with consistent format.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR)
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
        force=True
    )

    redact_filter = RedactSecretsFilter()

    # Application logs propagate to the root handler. The formatter also
    # redacts exception tracebacks, which record filters cannot rewrite.
    for handler in logging.getLogger().handlers:
        handler.addFilter(redact_filter)
        handler.setFormatter(RedactingFormatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

    # Uvicorn configures its own handlers; attach to the loggers as well so
    # access/error records are filtered regardless of handler configuration.
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logging.getLogger(logger_name).addFilter(redact_filter)

    # Reduce noise from chatty libraries
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


__all__ = ["configure_logging", "redact_secrets", "RedactSecretsFilter"]
