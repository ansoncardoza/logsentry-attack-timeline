
import pytest

from src.parsers.auth_parser import parse_auth_log


def test_parse_valid_auth_entry():
    line = (
        "Nov 10 09:15:22 server01 "
        "sshd[2451]: Failed password for invalid user admin "
        "from 203.0.113.50 port 51234 ssh2"
    )

    result = parse_auth_log(line)

    assert result["hostname"] == "server01"
    assert result["process_id"] == 2451
    assert result["result"] == "Failed"
    assert result["method"] == "password"
    assert result["username"] == "admin"
    assert result["invalid_user"] is True
    assert result["source_ip"] == "203.0.113.50"
    assert result["source_port"] == 51234


def test_parse_successful_auth_entry():
    line = (
        "Nov 10 09:10:12 server01 "
        "sshd[2101]: Accepted password for anson "
        "from 192.168.1.20 port 50122 ssh2"
    )

    result = parse_auth_log(line)

    assert result["result"] == "Accepted"
    assert result["username"] == "anson"
    assert result["invalid_user"] is False


def test_parse_invalid_auth_log_format():
    line = "This is not a valid authentication log"

    with pytest.raises(ValueError, match="Invalid authentication log format"):
        parse_auth_log(line)


def test_parse_invalid_auth_timestamp():
    line = (
        "Nov 32 09:15:22 server01 "
        "sshd[2451]: Failed password for admin "
        "from 203.0.113.50 port 51234 ssh2"
    )

    with pytest.raises(ValueError, match="Invalid authentication timestamp"):
        parse_auth_log(line)


def test_parse_empty_auth_entry():
    with pytest.raises(ValueError, match="Invalid authentication log format"):
        parse_auth_log("")


def test_parse_invalid_month():
    line = (
        "Xyz 10 09:15:22 server01 "
        "sshd[2451]: Failed password for admin "
        "from 203.0.113.50 port 51234 ssh2"
    )

    with pytest.raises(ValueError, match="Invalid authentication timestamp"):
        parse_auth_log(line)



def test_parse_invalid_source_port():
    line = (
        "Nov 10 09:15:22 server01 "
        "sshd[2451]: Failed password for admin "
        "from 203.0.113.50 port 99999 ssh2"
    )

    with pytest.raises(
        ValueError,
        match="Invalid authentication source port"
    ):
        parse_auth_log(line)