"""Logging setup: minimal console, verbose file log in workspace."""
import logging
import sys
from pathlib import Path

_CONSOLE_FMT = "[%(levelname).1s] %(message)s"
_FILE_FMT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

log = logging.getLogger("pocsmith")


def init(workspace: Path) -> None:
    """Call once at session start. Idempotent if called again with same workspace."""
    if log.handlers:
        return

    log.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(_CONSOLE_FMT))

    log_path = workspace / "pocsmith.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_FILE_FMT))

    log.addHandler(console)
    log.addHandler(file_handler)
    log.info("Log file: %s", log_path)
