"""Structured logging, sized for volume.

The app this replaces logged two INFO lines plus the full OpenCTI result per
request. At 1000 lookups/sec that is a meaningful share of CPU and gigabytes
of disk an hour. Here the request path logs nothing at INFO -- counters carry
it -- and only genuine upstream calls and failures produce a line.
"""

from __future__ import annotations

import logging
import sys

import structlog


def configure(level: str = "INFO", fmt: str = "json") -> None:
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if fmt == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(
        format="%(message)s", stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    # uvicorn's access log duplicates what our counters already track.
    logging.getLogger("uvicorn.access").disabled = True
