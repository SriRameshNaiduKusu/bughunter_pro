"""
BugHunter Pro - Centralized Logging Module
"""

import logging
import os
import sys
from datetime import datetime
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


class ColorFormatter(logging.Formatter):
    """Custom formatter that adds color to console output."""

    COLOURS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        colour = self.COLOURS.get(record.levelno, "")
        record.msg = f"{colour}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(
    name: str = "bughunter",
    output_dir: str = "bughunter_output",
    verbose: bool = False,
) -> logging.Logger:
    """Create and return a configured logger instance."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_fmt = ColorFormatter(
        "[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%H:%M:%S"
    )
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(output_dir, f"bughunter_{timestamp}.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s [%(module)s] %(message)s"
    )
    file_handler.setFormatter(file_fmt)
    logger.addHandler(file_handler)

    return logger