import pytest
from netscan.utils.validators import (
    ValidationError, validate_target, validate_ports, validate_timeout
)
from netscan.utils.network import parse_port_expression


def test_valid_ipv4():
    assert validate_target("192.168.1.1") == "192.168.1.1"

def test_valid_cidr():
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"

def test_invalid_target_raises():
    with pytest.raises(ValidationError):
        validate_target("not_a_host!!")

def test_port_range_parsing():
    assert parse_port_expression("80,443") == [80, 443]
    assert parse_port_expression("1-5") == [1, 2, 3, 4, 5]
    assert parse_port_expression("22,80-82") == [22, 80, 81, 82]

def test_invalid_port_range():
    with pytest.raises(ValidationError):
        parse_port_expression("100-50")   # reversed range

def test_timeout_bounds():
    with pytest.raises(ValidationError):
        validate_timeout(0.0)
    with pytest.raises(ValidationError):
        validate_timeout(999.0)