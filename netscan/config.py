# netscan/config.py

from dataclasses import dataclass

from netscan.core.models import ScanType
from netscan.utils.validators import (
    validate_ports,
    validate_target,
    validate_threads,
    validate_timeout,
)


DEFAULT_TIMEOUT   = 1.0
DEFAULT_THREADS   = 100
DEFAULT_TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     3306, 3389, 5432, 6379, 8080, 8443, 27017]


@dataclass
class ScanConfig:
    target:      str
    ports:       list[int]
    scan_type:   ScanType = ScanType.TCP_CONNECT
    timeout:     float    = DEFAULT_TIMEOUT
    threads:     int      = DEFAULT_THREADS
    output_dir:  str      = "./results"
    verbose:     bool     = False
    grab_banner: bool     = True

    def __post_init__(self):
        """Validate all fields on construction."""
        self.target  = validate_target(self.target)
        self.ports   = validate_ports(self.ports)
        self.threads = validate_threads(self.threads)
        self.timeout = validate_timeout(self.timeout)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        """Construct from a plain dictionary — useful for testing."""
        return cls(**data)