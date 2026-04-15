from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"


class ScanType(str, Enum):
    TCP_CONNECT = "tcp_connect"
    SYN         = "syn"


@dataclass
class PortResult:
    port:         int
    state:        PortState
    service:      str        = ""
    banner:       str        = ""
    scan_time_ms: float      = 0.0

    def is_open(self) -> bool:
        return self.state == PortState.OPEN


@dataclass
class ScanResult:
    target:     str
    scan_type:  ScanType
    started_at: datetime         = field(default_factory=datetime.utcnow)
    ended_at:   datetime | None  = None
    ports:      list[PortResult] = field(default_factory=list)

    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open()]

    def duration_seconds(self) -> float | None:
        if self.ended_at:
            return (self.ended_at - self.started_at).total_seconds()
        return None

    def summary(self) -> dict:
        return {
            "target":        self.target,
            "scan_type":     self.scan_type.value,
            "total_scanned": len(self.ports),
            "open":          len(self.open_ports()),
            "started_at":    self.started_at.isoformat(),
            "duration_s":    self.duration_seconds(),
        }