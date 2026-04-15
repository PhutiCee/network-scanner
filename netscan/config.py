from dataclasses import dataclass, field
from netscan.core.models import ScanType

# seconds per port
DEFAULT_TIMEOUT   = 1.0

DEFAULT_THREADS   = 100
DEFAULT_TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     3306, 3389, 5432, 6379, 8080, 8443, 27017]


@dataclass
class ScanConfig:
    target:      str
    ports:       list[int]
    scan_type:   ScanType  = ScanType.TCP_CONNECT
    timeout:     float     = DEFAULT_TIMEOUT
    threads:     int       = DEFAULT_THREADS
    output_dir:  str       = "./results"
    verbose:     bool      = False
    grab_banner: bool      = True