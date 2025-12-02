import logging
import os
from logging.config import dictConfig


def setup_logging() -> None:
    """Ensure sane logging to stdout for app and uvicorn.

    - Respects CHATAPP_LOG_LEVEL (default INFO)
    - Leaves existing handlers intact if already configured (e.g., when uvicorn provides config)
    """
    root = logging.getLogger()
    # If handlers already exist, assume another runner (like uvicorn) configured logging.
    if root.handlers:
        # Still make sure level isn't too high
        try:
            lvl = os.environ.get("CHATAPP_LOG_LEVEL", "INFO").upper()
            root.setLevel(getattr(logging, lvl, logging.INFO))
        except Exception:
            pass
        return

    level_name = os.environ.get("CHATAPP_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {
            # Ensure uvicorn logs go to console if present
            "uvicorn": {"handlers": ["console"], "level": level, "propagate": False},
            "uvicorn.error": {"handlers": ["console"], "level": level, "propagate": False},
            "uvicorn.access": {"handlers": ["console"], "level": level, "propagate": False},
        },
        "root": {"handlers": ["console"], "level": level},
    }

    try:
        dictConfig(config)
    except Exception:
        # Fallback to a very simple config
        logging.basicConfig(level=level, format="%(levelname)s:%(name)s:%(message)s")
