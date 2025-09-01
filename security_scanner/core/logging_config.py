"""
Logging configuration for the security scanner service.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
    enable_console: bool = True
) -> logging.Logger:
    """
    Set up logging configuration for the security scanner.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        log_format: Optional custom log format
        enable_console: Whether to enable console logging
    
    Returns:
        Configured logger instance
    """
    
    # Default log format
    if log_format is None:
        log_format = (
            "%(asctime)s - %(name)s - %(levelname)s - "
            "[%(filename)s:%(lineno)d] - %(message)s"
        )
    
    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create root logger
    logger = logging.getLogger("security_scanner")
    logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(log_format)
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(f"security_scanner.{name}")


class ScanProgressLogger:
    """Logger for tracking scan progress."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.current_target = None
        self.current_scanner = None
    
    def start_target(self, target: str, target_type: str):
        """Log start of target scanning."""
        self.current_target = target
        self.logger.info(f"Starting scan of {target_type}: {target}")
    
    def start_scanner(self, scanner_name: str):
        """Log start of scanner execution."""
        self.current_scanner = scanner_name
        self.logger.info(f"  Running {scanner_name} scanner...")
    
    def scanner_completed(self, scanner_name: str, findings_count: int, duration: float):
        """Log scanner completion."""
        self.logger.info(
            f"  ✓ {scanner_name} completed in {duration:.2f}s - "
            f"{findings_count} findings"
        )
    
    def scanner_failed(self, scanner_name: str, error: str):
        """Log scanner failure."""
        self.logger.error(f"  ✗ {scanner_name} failed: {error}")
    
    def scanner_skipped(self, scanner_name: str, reason: str):
        """Log scanner skip."""
        self.logger.warning(f"  - {scanner_name} skipped: {reason}")
    
    def target_completed(self, target: str, total_findings: int, duration: float):
        """Log target completion."""
        self.logger.info(
            f"Completed scan of {target} in {duration:.2f}s - "
            f"{total_findings} total findings"
        )
    
    def scan_summary(self, total_targets: int, total_findings: int, duration: float):
        """Log overall scan summary."""
        self.logger.info(
            f"Scan completed: {total_targets} targets, "
            f"{total_findings} total findings in {duration:.2f}s"
        )


def configure_third_party_loggers(log_level: str = "WARNING"):
    """
    Configure logging for third-party libraries to reduce noise.
    
    Args:
        log_level: Log level for third-party loggers
    """
    third_party_loggers = [
        "urllib3",
        "requests",
        "docker",
        "paramiko",
        "boto3",
        "botocore"
    ]
    
    numeric_level = getattr(logging, log_level.upper(), logging.WARNING)
    
    for logger_name in third_party_loggers:
        logging.getLogger(logger_name).setLevel(numeric_level)