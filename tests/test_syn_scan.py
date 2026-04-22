import pytest
from unittest.mock import MagicMock, patch
from netscan.core.models import PortState


# ── Environment checks ────────────────────────────────────────────────────────

def test_syn_scanner_raises_without_scapy():
    with patch("netscan.scanner.syn_scan._is_scapy_available", return_value=False):
        with patch("netscan.scanner.syn_scan._has_root_privileges", return_value=True):
            from netscan.scanner.syn_scan import SYNScanner
            with pytest.raises(EnvironmentError, match="scapy is not installed"):
                SYNScanner()


def test_syn_scanner_raises_without_privileges():
    with patch("netscan.scanner.syn_scan._is_scapy_available", return_value=True):
        with patch("netscan.scanner.syn_scan._has_root_privileges", return_value=False):
            from netscan.scanner.syn_scan import SYNScanner
            with pytest.raises(EnvironmentError, match="Administrator"):
                SYNScanner()


# ── Response interpretation ───────────────────────────────────────────────────

@pytest.fixture
def scanner():
    """Build a SYNScanner with all environment checks bypassed."""
    with patch("netscan.scanner.syn_scan._is_scapy_available", return_value=True):
        with patch("netscan.scanner.syn_scan._has_root_privileges", return_value=True):
            with patch("netscan.scanner.syn_scan.SYNScanner.__init__",
                       lambda self, timeout=1.0: (
                           BaseScanner.__init__(self, timeout) or  # type: ignore
                           setattr(self, "_conf", MagicMock()) or
                           setattr(self, "_IP",   MagicMock()) or
                           setattr(self, "_TCP",  MagicMock()) or
                           setattr(self, "_sr1",  MagicMock())
                       )):
                from netscan.scanner.syn_scan import SYNScanner
                from netscan.scanner.base import BaseScanner
                s = SYNScanner.__new__(SYNScanner)
                s.timeout = 1.0
                s._conf   = MagicMock()
                s._IP     = MagicMock()
                s._TCP    = MagicMock()
                s._sr1    = MagicMock()
                return s


def make_tcp_response(flags: int):
    """Build a mock scapy response with specific TCP flags."""
    mock_tcp   = MagicMock()
    mock_tcp.flags = flags
    mock_resp  = MagicMock()
    mock_resp.haslayer.side_effect = lambda layer: layer.__name__ == "TCP" \
        if hasattr(layer, "__name__") else True
    mock_resp.__getitem__ = lambda self, key: mock_tcp
    return mock_resp


def test_syn_ack_response_returns_open(scanner):
    response = make_tcp_response(flags=0x12)  # SYN+ACK
    with patch.object(scanner, "_send_rst"):
        result = scanner._interpret_response(response, "127.0.0.1", 80)
    assert result == PortState.OPEN


def test_rst_response_returns_closed(scanner):
    response = make_tcp_response(flags=0x14)  # RST+ACK
    result = scanner._interpret_response(response, "127.0.0.1", 80)
    assert result == PortState.CLOSED


def test_no_response_returns_filtered(scanner):
    result = scanner._interpret_response(None, "127.0.0.1", 80)
    assert result == PortState.FILTERED


# ── Engine fallback ───────────────────────────────────────────────────────────

def test_engine_falls_back_to_tcp_on_missing_privileges():
    from netscan.config import ScanConfig
    from netscan.core.engine import ScanEngine
    from netscan.core.models import ScanType

    config = ScanConfig(
        target    = "127.0.0.1",
        ports     = [80],
        scan_type = ScanType.SYN,
        timeout   = 0.5,
    )

    with patch("netscan.scanner.syn_scan.SYNScanner", side_effect=EnvironmentError("no privileges")):
        engine = ScanEngine(config)

    # Should have fallen back — scanner is TCPConnectScanner not SYNScanner
    from netscan.scanner.tcp_connect import TCPConnectScanner
    assert isinstance(engine.scanner, TCPConnectScanner)