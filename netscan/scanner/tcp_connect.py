import socket
import time

from netscan.core.models import PortResult, PortState
from netscan.output.logger import get_logger
from netscan.scanner.base import BaseScanner

logger = get_logger(__name__)

# errno codes returned by connect_ex() on different OS/states
_CONN_REFUSED = 111   # Linux
_CONN_RESET   = 104   # Linux - RST from server


class TCPConnectScanner(BaseScanner):
    """
    Performs a full TCP 3-way handshake to determine port state.

    Pros:  No root required. Reliable. Works through most firewalls.
    Cons:  Completes the full handshake - leaves log entries on target.
           Slower than SYN scan for large port ranges.
    """

    def __init__(self, timeout: float = 1.0, grab_banner: bool = True):
        super().__init__(timeout)
        self.grab_banner = grab_banner

    def scan_port(self, target: str, port: int) -> PortResult:
        start = time.perf_counter()
        state, banner = self._connect(target, port)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return PortResult(
            port=port,
            state=state,
            banner=banner,
            scan_time_ms=round(elapsed_ms, 2),
        )

    def _connect(self, target: str, port: int) -> tuple[PortState, str]:
        """
        Core connection logic. Returns (PortState, banner_string).
        Isolated from scan_port so it can be tested independently.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result_code = sock.connect_ex((target, port))

            if result_code == 0:
                # Connection succeeded - port is open
                banner = self._grab_banner(sock) if self.grab_banner else ""
                return PortState.OPEN, banner

            # connect_ex returns errno on failure
            # ECONNREFUSED means the host actively rejected - port is closed
            if result_code in (_CONN_REFUSED, _CONN_RESET):
                return PortState.CLOSED, ""

            # Any other error code - firewall drop, unreachable, etc.
            return PortState.FILTERED, ""

        except socket.timeout:
            # No response within timeout window - likely filtered
            logger.debug("Timeout on %s:%d", target, port)
            return PortState.FILTERED, ""

        except socket.gaierror as e:
            # DNS resolution failed or invalid address
            logger.warning("Address error for %s: %s", target, e)
            return PortState.FILTERED, ""

        except OSError as e:
            # Catch-all for unexpected socket errors
            logger.debug("OSError on %s:%d - %s", target, port, e)
            return PortState.FILTERED, ""

        finally:
            # Always close - even on exception paths
            sock.close()

    def _grab_banner(self, sock: socket.socket) -> str:
        """
        Attempt to read a service banner from an open socket.
        Returns empty string if the service sends nothing.
        """
        try:
            # Some services (HTTP) need a prompt before they respond
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            logger.debug("Banner received: %s", banner[:80])
            return banner
        except (socket.timeout, OSError):
            return ""