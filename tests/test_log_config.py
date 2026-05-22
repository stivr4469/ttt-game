"""Тесты для log_config.py — JSON-форматирование, get_logger."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import logging
import pytest
from log_config import JsonFormatter, get_logger


class TestJsonFormatter:
    def _make_record(self, msg: str, level=logging.INFO, **kwargs) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test.logger", level=level,
            pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )
        for k, v in kwargs.items():
            setattr(record, k, v)
        return record

    def test_output_is_valid_json(self):
        fmt = JsonFormatter()
        record = self._make_record("hello world")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_required_fields(self):
        fmt = JsonFormatter()
        record = self._make_record("test message")
        parsed = json.loads(fmt.format(record))
        assert "ts" in parsed
        assert "level" in parsed
        assert "logger" in parsed
        assert "msg" in parsed

    def test_level_string(self):
        fmt = JsonFormatter()
        record = self._make_record("warn msg", level=logging.WARNING)
        parsed = json.loads(fmt.format(record))
        assert parsed["level"] == "WARNING"

    def test_message_content(self):
        fmt = JsonFormatter()
        record = self._make_record("specific message content")
        parsed = json.loads(fmt.format(record))
        assert parsed["msg"] == "specific message content"

    def test_logger_name(self):
        fmt = JsonFormatter()
        record = self._make_record("msg")
        parsed = json.loads(fmt.format(record))
        assert parsed["logger"] == "test.logger"

    def test_ensure_ascii_false(self):
        fmt = JsonFormatter()
        record = self._make_record("Кириллица в логах")
        output = fmt.format(record)
        assert "Кириллица в логах" in output  # не экранированные unicode-коды

    def test_single_line_output(self):
        fmt = JsonFormatter()
        record = self._make_record("single line test")
        output = fmt.format(record)
        assert "\n" not in output


class TestGetLogger:
    def test_returns_logger_instance(self):
        log = get_logger("test.module")
        assert isinstance(log, logging.Logger)

    def test_logger_name(self):
        log = get_logger("my.custom.logger")
        assert log.name == "my.custom.logger"

    def test_idempotent_no_duplicate_handlers(self):
        log1 = get_logger("idempotent.test")
        log2 = get_logger("idempotent.test")
        assert log1 is log2
        assert len(log1.handlers) == 1

    def test_propagate_disabled(self):
        log = get_logger("propagate.test")
        assert log.propagate is False

    def test_default_level_info(self):
        log = get_logger("level.test.info")
        assert log.level == logging.INFO

    def test_custom_level(self):
        log = get_logger("level.test.debug", level=logging.DEBUG)
        assert log.level == logging.DEBUG

    def test_handler_uses_json_formatter(self):
        log = get_logger("formatter.test")
        handler = log.handlers[0]
        assert isinstance(handler.formatter, JsonFormatter)
