"""
Структурированное JSON-логирование для всех агентов.
Использование: from log_config import get_logger; log = get_logger(__name__)
"""

import logging
import json
import sys
from datetime import datetime, timezone


_STANDARD_LOG_ATTRS = frozenset({
    "args", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "message", "module", "msecs", "msg",
    "name", "pathname", "process", "processName", "relativeCreated",
    "stack_info", "thread", "threadName", "taskName",
})


class JsonFormatter(logging.Formatter):
    """Выводит каждое log-сообщение как одну строку JSON для ELK/Loki."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # захватываем extra-поля переданные через logging.xxx(..., extra={...})
        for key, val in record.__dict__.items():
            if key not in _STANDARD_LOG_ATTRS and not key.startswith("_"):
                try:
                    json.dumps(val)
                    payload[key] = val
                except (TypeError, ValueError):
                    payload[key] = str(val)
        return json.dumps(payload, ensure_ascii=False)


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
