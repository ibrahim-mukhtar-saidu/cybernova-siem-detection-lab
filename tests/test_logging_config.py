import logging

import pytest

from engine.logging_config import DATE_FORMAT, LOG_FORMAT, configure_logging


@pytest.fixture
def clean_root_logger():
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    yield root_logger

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    for handler in original_handlers:
        root_logger.addHandler(handler)

    root_logger.setLevel(original_level)


def test_configure_logging_sets_debug_level_and_format(clean_root_logger):
    configure_logging(level=logging.DEBUG)

    assert clean_root_logger.level == logging.DEBUG
    assert clean_root_logger.handlers

    assert any(
        handler.formatter is not None
        and handler.formatter._fmt == LOG_FORMAT
        and handler.formatter.datefmt == DATE_FORMAT
        for handler in clean_root_logger.handlers
    )


def test_configure_logging_defaults_to_info_level(clean_root_logger):
    configure_logging()

    assert clean_root_logger.level == logging.INFO
