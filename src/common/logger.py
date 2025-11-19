"""Logging infrastructure for safe-apt.

Provides centralized logging configuration with support for both
file and console output, log rotation, and ISO 8601 timestamps.
"""

import logging
import logging.handlers
import os
from typing import Optional


def setup_logger(
    name: str,
    log_dir: str = "/opt/apt-mirror-system/logs",
    level: str = "INFO",
    log_format: Optional[str] = None,
    date_format: Optional[str] = None,
    file_logging: bool = True,
    console_logging: bool = True,
    max_bytes: int = 10485760,  # 10MB
    backup_count: int = 5,
) -> logging.Logger:
    """Set up a logger with file and console handlers.

    Args:
        name: Logger name (typically module or component name)
        log_dir: Directory for log files
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Custom log format string
        date_format: Custom date format string (ISO 8601 by default)
        file_logging: Enable file logging
        console_logging: Enable console logging
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup log files to keep

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Validate and set log level
    level_upper = level.upper()
    if not hasattr(logging, level_upper):
        raise ValueError(
            f"Invalid log level: {level}. "
            f"Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
        )
    logger.setLevel(getattr(logging, level_upper))

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Default formats
    if log_format is None:
        log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    if date_format is None:
        date_format = "%Y-%m-%dT%H:%M:%S"

    formatter = logging.Formatter(log_format, datefmt=date_format)

    # File handler with rotation
    if file_logging:
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"{name}.log")
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Console handler
    if console_logging:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get an existing logger by name.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
