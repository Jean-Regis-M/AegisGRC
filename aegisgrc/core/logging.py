import logging
import sys
from aegisgrc.core.config import settings


def setup_logging() -> logging.Logger:
    """Configures centralized logs format matching standard container stdout."""
    logger = logging.getLogger("aegis_grc")
    logger.setLevel(settings.LOG_LEVEL)
    
    # Avoid duplicate logs handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger


logger = setup_logging()
