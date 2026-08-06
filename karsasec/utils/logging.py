"""Console logger module powered by Rich."""

import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console()
error_console = Console(stderr=True)

def setup_logger(level: str = "INFO") -> logging.Logger:
    """Configures and returns the application logger."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                show_path=False,
                markup=True
            )
        ]
    )
    return logging.getLogger("karsasec")

logger = setup_logger()
