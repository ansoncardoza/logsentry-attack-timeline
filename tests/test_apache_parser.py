
import pytest

from src.parsers.apache_parser import parse_apache_log


def test_parse_valid_apache_entry():
    line = (
        '203.0.113.60 - - '
        '[10/Nov/2026:09:35:02 +0000] '
        '"GET /.env HTTP/1.1" 404 512'
    )

    result = parse_apache_log(line)

    assert result["source_ip"] == "203.0.113.60"
    assert result["method"] == "GET"
    assert result["path"] == "/.env"
    assert result["protocol"] == "HTTP/1.1"
    assert result["status_code"] == 404
    assert result["response_size"] == 512


def test_parse_invalid_log_format():
    line = "This is not a valid Apache log entry"

    with pytest.raises(ValueError):
        parse_apache_log(line)


def test_parse_invalid_timestamp():
    line = (
        '203.0.113.60 - - '
        '[32/Nov/2026:09:35:02 +0000] '
        '"GET /.env HTTP/1.1" 404 512'
    )

    with pytest.raises(ValueError, match="Invalid Apache timestamp"):
        parse_apache_log(line)


def test_parse_missing_response_size():
    line = (
        '203.0.113.60 - - '
        '[10/Nov/2026:09:35:02 +0000] '
        '"GET /.env HTTP/1.1" 404 -'
    )

    result = parse_apache_log(line)

    assert result["response_size"] is None

def test_parse_empty_log_entry():
    with pytest.raises(ValueError, match="Invalid Apache access log format"):
        parse_apache_log("")


def test_parse_incomplete_http_request():
    line = (
        '203.0.113.60 - - '
        '[10/Nov/2026:09:35:02 +0000] '
        '"GET /.env HTTP/1.1"'
    )

    with pytest.raises(ValueError):
        parse_apache_log(line)


def test_parse_request_with_query_string():
    line = (
        '203.0.113.60 - - '
        '[10/Nov/2026:09:35:02 +0000] '
        '"GET /search?q=admin HTTP/1.1" 200 1024'
    )

    result = parse_apache_log(line)

    assert result["path"] == "/search?q=admin"
    assert result["status_code"] == 200
    assert result["response_size"] == 1024


def test_parse_rejects_unexpected_trailing_data():
    line = (
        '203.0.113.60 - - '
        '[10/Nov/2026:09:35:02 +0000] '
        '"GET /.env HTTP/1.1" 404 512 EXTRA'
    )

    with pytest.raises(ValueError):
        parse_apache_log(line)
