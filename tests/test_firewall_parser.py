
import pytest

from src.parsers.firewall_parser import parse_firewall_log


def test_parse_valid_firewall_entry():
    line = (
        "Nov 10 10:00:01 server01 kernel: [UFW BLOCK] "
        "IN=eth0 OUT= SRC=203.0.113.70 DST=192.168.1.100 "
        "PROTO=TCP SPT=51001 DPT=22"
    )

    result = parse_firewall_log(line)

    assert result["hostname"] == "server01"
    assert result["action"] == "BLOCK"
    assert result["interface"] == "eth0"
    assert result["source_ip"] == "203.0.113.70"
    assert result["destination_ip"] == "192.168.1.100"
    assert result["protocol"] == "TCP"
    assert result["source_port"] == 51001
    assert result["destination_port"] == 22


def test_parse_firewall_entry_with_bom():
    line = (
        "\ufeffNov 10 10:00:01 server01 kernel: [UFW BLOCK] "
        "IN=eth0 OUT= SRC=203.0.113.70 DST=192.168.1.100 "
        "PROTO=TCP SPT=51001 DPT=22"
    )

    result = parse_firewall_log(line)

    assert result["source_ip"] == "203.0.113.70"
    assert result["destination_port"] == 22


def test_parse_invalid_firewall_log_format():
    line = "This is not a valid firewall log"

    with pytest.raises(ValueError, match="Invalid firewall log format"):
        parse_firewall_log(line)


def test_parse_invalid_firewall_timestamp():
    line = (
        "Nov 32 10:00:01 server01 kernel: [UFW BLOCK] "
        "IN=eth0 OUT= SRC=203.0.113.70 DST=192.168.1.100 "
        "PROTO=TCP SPT=51001 DPT=22"
    )

    with pytest.raises(ValueError, match="Invalid firewall timestamp"):
        parse_firewall_log(line)
