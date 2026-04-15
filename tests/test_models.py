from netscan.core.models import PortResult, PortState, ScanResult, ScanType

def test_port_result_is_open():
    r = PortResult(port=80, state=PortState.OPEN)
    assert r.is_open() is True


def test_port_result_closed_is_not_open():
    r = PortResult(port=80, state=PortState.CLOSED)
    assert r.is_open() is False


def test_scan_result_open_ports_filter():
    result = ScanResult(target="127.0.0.1", scan_type=ScanType.TCP_CONNECT)
    result.ports = [
        PortResult(port=22,  state=PortState.OPEN),
        PortResult(port=23,  state=PortState.CLOSED),
        PortResult(port=443, state=PortState.FILTERED),
    ]
    assert len(result.open_ports()) == 1
    assert result.open_ports()[0].port == 22


def test_summary_keys():
    result = ScanResult(target="10.0.0.1", scan_type=ScanType.SYN)
    s = result.summary()
    for key in ("target", "scan_type", "total_scanned", "open"):
        assert key in s