import logging
import sys
from pathlib import Path


def setup_logger(verbose: bool = False, log_file: str | None = None) -> logging.Logger:
    """
    Configure and return the root netscan logger.

    - Console: WARNING level by default, DEBUG if verbose
    - File:    DEBUG level always (if log_file is provided)
    """
    logger = logging.getLogger("network-scan")
    logger.setLevel(logging.DEBUG)  # capture everything; handlers filter

    formatter = logging.Formatter(
        fmt="[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler (optional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a child logger for a specific module.
    Usage: logger = get_logger(__name__)
    """
    return logging.getLogger(f"netscan.{name}")