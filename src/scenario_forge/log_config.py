"""Centralized logging configuration for scenario-forge."""

from __future__ import annotations

import json
import logging
from pathlib import Path

_HUMAN_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
_HUMAN_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

_LOGGER_NAME = "scenario_forge"


class _JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": self.formatTime(record, _HUMAN_DATE_FORMAT),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(entry, default=str)


def setup_logging(
    log_level: str = "INFO",
    output_dir: Path | None = None,
    structured: bool = False,
) -> None:
    """Configure the ``scenario_forge`` logger hierarchy.

    Parameters
    ----------
    log_level:
        Minimum level for the **console** (stderr) handler.
        One of ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``.
    output_dir:
        Directory for the ``pipeline.log`` file.  When *None* the file
        handler is skipped (useful for commands that write to stdout).
    structured:
        When *True* the **file** handler uses JSON-lines format.
        The console handler is always human-readable.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)  # allow all; handlers decide

    # Prevent duplicate handlers when called more than once
    # (e.g. tests or repeated CLI invocations in the same process).
    logger.handlers.clear()

    # -- stderr console handler (always human-readable) --
    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    console.setFormatter(
        logging.Formatter(_HUMAN_FORMAT, datefmt=_HUMAN_DATE_FORMAT)
    )
    logger.addHandler(console)

    # -- file handler (DEBUG, optional structured format) --
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / "pipeline.log"

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)

        if structured:
            file_handler.setFormatter(_JsonFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter(_HUMAN_FORMAT, datefmt=_HUMAN_DATE_FORMAT)
            )

        logger.addHandler(file_handler)
