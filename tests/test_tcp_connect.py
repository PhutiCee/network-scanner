import socket
from unittest.mock import MagicMock, patch

import pytest

from netscan.core.models import PortState
from netscan.scanner.tcp_connect import TCPConnectScanner
from netscan.scanner.banner import identify_service


@pytest.fixture
def scanner():
    return TCPConnectScanner(timeout=0.5, grab_banner=False)


def make_mock_socket(connect_ex_return: int, recv_data: bytes = b""):
    """Helper: build a mock socket with controlled behaviour."""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = connect_ex_return
    mock_sock.recv.return_value = recv_data
    return mock_sock


@patch("netscan.scanner.tcp_connect.socket.socket")
def test_open_port_returns_open_state(mock_socket_cls, scanner):
    mock_socket_cls.return_value.__enter__ = lambda s: s
    mock_socket_cls.return_value = make_mock_socket(connect_ex_return=0)

    result = scanner.scan_port("127.0.0.1", 80)

    assert result.port == 80
    assert result.state == PortState.OPEN


@patch("netscan.scanner.tcp_connect.socket.socket")
def test_refused_port_returns_closed(mock_socket_cls, scanner):
    mock_socket_cls.return_value = make_mock_socket(connect_ex_return=111)

    result = scanner.scan_port("127.0.0.1", 9999)

    assert result.state == PortState.CLOSED


@patch("netscan.scanner.tcp_connect.socket.socket")
def test_timeout_returns_filtered(mock_socket_cls, scanner):
    mock_sock = MagicMock()
    mock_sock.connect_ex.side_effect = socket.timeout
    mock_socket_cls.return_value = mock_sock

    result = scanner.scan_port("127.0.0.1", 81)

    assert result.state == PortState.FILTERED


@patch("netscan.scanner.tcp_connect.socket.socket")
def test_scan_time_is_recorded(mock_socket_cls, scanner):
    mock_socket_cls.return_value = make_mock_socket(connect_ex_return=0)

    result = scanner.scan_port("127.0.0.1", 22)

    assert result.scan_time_ms >= 0


@patch("netscan.scanner.tcp_connect.socket.socket")
def test_oserror_returns_filtered(mock_socket_cls, scanner):
    mock_sock = MagicMock()
    mock_sock.connect_ex.side_effect = OSError("network unreachable")
    mock_socket_cls.return_value = mock_sock

    result = scanner.scan_port("10.0.0.1", 22)

    assert result.state == PortState.FILTERED



def test_ssh_banner_identified():
    assert identify_service(22, "SSH-2.0-OpenSSH_8.9") == "ssh"

def test_http_banner_identified():
    assert identify_service(80, "HTTP/1.1 200 OK") == "http"

def test_fallback_to_well_known_port():
    assert identify_service(443, "") == "https"

def test_unknown_port_no_banner_returns_empty():
    assert identify_service(54321, "") == ""

def test_banner_takes_priority_over_port():
    # SSH running on port 80 — banner wins
    assert identify_service(80, "SSH-2.0-OpenSSH_8.9") == "ssh"