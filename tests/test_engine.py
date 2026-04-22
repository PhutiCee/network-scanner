from unittest.mock import MagicMock, patch
from netscan.config import ScanConfig
from netscan.core.engine import ScanEngine
from netscan.core.models import PortResult, PortState, ScanType


def make_config(ports: list[int], threads: int = 10) -> ScanConfig:
    return ScanConfig(
        target  = "127.0.0.1",
        ports   = ports,
        threads = threads,
        timeout = 0.5,
    )


def make_port_result(port: int, state: PortState) -> PortResult:
    return PortResult(port=port, state=state, scan_time_ms=1.0)


# Engine result collection

@patch("netscan.core.engine.TCPConnectScanner")
def test_engine_collects_all_results(mock_scanner_cls):
    """Engine should return one PortResult per port submitted."""
    mock_scanner = MagicMock()
    mock_scanner.scan_port.side_effect = lambda target, port: \
        make_port_result(port, PortState.OPEN)
    mock_scanner_cls.return_value = mock_scanner

    config = make_config(ports=[80, 443, 22])
    engine = ScanEngine(config)
    result = engine.run()

    assert len(result.ports) == 3


@patch("netscan.core.engine.TCPConnectScanner")
def test_engine_results_sorted_by_port(mock_scanner_cls):
    """Ports should be in ascending order regardless of thread completion."""
    mock_scanner = MagicMock()
    mock_scanner.scan_port.side_effect = lambda target, port: \
        make_port_result(port, PortState.OPEN)
    mock_scanner_cls.return_value = mock_scanner

    config = make_config(ports=[443, 22, 80])
    engine = ScanEngine(config)
    result = engine.run()

    ports = [r.port for r in result.ports]
    assert ports == sorted(ports)


@patch("netscan.core.engine.TCPConnectScanner")
def test_engine_open_ports_filtered_correctly(mock_scanner_cls):
    """open_ports() should only return OPEN state results."""
    def fake_scan(target, port):
        state = PortState.OPEN if port == 80 else PortState.CLOSED
        return make_port_result(port, state)

    mock_scanner = MagicMock()
    mock_scanner.scan_port.side_effect = fake_scan
    mock_scanner_cls.return_value = mock_scanner

    config = make_config(ports=[80, 443, 22])
    engine = ScanEngine(config)
    result = engine.run()

    assert len(result.open_ports()) == 1
    assert result.open_ports()[0].port == 80


@patch("netscan.core.engine.TCPConnectScanner")
def test_engine_records_duration(mock_scanner_cls):
    """ScanResult should have both started_at and ended_at after run()."""
    mock_scanner = MagicMock()
    mock_scanner.scan_port.return_value = make_port_result(80, PortState.OPEN)
    mock_scanner_cls.return_value = mock_scanner

    config = make_config(ports=[80])
    engine = ScanEngine(config)
    result = engine.run()

    assert result.ended_at is not None
    assert result.duration_seconds() >= 0


@patch("netscan.core.engine.TCPConnectScanner")
def test_progress_callback_called_for_each_port(mock_scanner_cls):
    """Progress callback should fire exactly once per port."""
    mock_scanner = MagicMock()
    mock_scanner.scan_port.side_effect = lambda t, p: \
        make_port_result(p, PortState.CLOSED)
    mock_scanner_cls.return_value = mock_scanner

    calls = []
    config = make_config(ports=[80, 443, 22, 8080])
    engine = ScanEngine(config)
    engine.run(progress_callback=lambda done, total: calls.append((done, total)))

    assert len(calls) == 4
    assert calls[-1] == (4, 4)  # last call should be (total, total)


# Config validation

def test_config_rejects_invalid_port():
    from netscan.utils.validators import ValidationError
    import pytest
    with pytest.raises(ValidationError):
        ScanConfig(target="127.0.0.1", ports=[99999])


def test_config_deduplicates_ports():
    config = ScanConfig(target="127.0.0.1", ports=[80, 80, 443])
    assert config.ports.count(80) == 1