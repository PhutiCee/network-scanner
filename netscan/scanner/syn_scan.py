import random
from netscan.core.models import PortResult, PortState
from netscan.output.logger import get_logger
from netscan.scanner.base import BaseScanner

logger = get_logger(__name__)

# TCP flag constants
TCP_SYN     = 0x02
TCP_ACK     = 0x10
TCP_RST     = 0x04
TCP_SYN_ACK = TCP_SYN | TCP_ACK   # 0x12
TCP_RST_ACK = TCP_RST | TCP_ACK   # 0x14


def _is_scapy_available() -> bool:
    """Check if scapy can be imported - fails gracefully if not installed."""
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


def _has_root_privileges() -> bool:
    """
    Check for raw socket privileges.
    Works on both Windows (admin check) and Unix (uid 0).
    """
    import os
    import ctypes

    # Unix
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    # Windows
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class SYNScanner(BaseScanner):
    """
    Performs a TCP SYN (half-open) scan using raw packets via scapy.

    Pros:  Never completes the TCP handshake - stealthier than TCP connect.
           Faster for large port ranges - no full connection overhead.
    Cons:  Requires root/Administrator privileges.
           Requires Npcap (Windows) or libpcap (Linux/Mac).
           May be detected by modern IDS/IPS systems.

    Raises:
        EnvironmentError: if scapy is unavailable or privileges are missing.
    """

    def __init__(self, timeout: float = 1.0):
        super().__init__(timeout)
        self._validate_environment()

        # I Import scapy here so the rest of the codebase can import this module without scapy being installed.
        from scapy.all import IP, TCP, sr1, conf
        self._IP   = IP
        self._TCP  = TCP
        self._sr1  = sr1
        self._conf = conf
        self._conf.verb = 0   # suppress scapy's own output

    def scan_port(self, target: str, port: int) -> PortResult:
        import time
        start = time.perf_counter()
        state = self._probe(target, port)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return PortResult(
            port         = port,
            state        = state,
            scan_time_ms = round(elapsed_ms, 2),
        )

    def _probe(self, target: str, port: int) -> PortState:
        """
        Send a SYN packet and interpret the response flags.
        Returns a PortState. Never raises.
        """
        try:
            # Use a random source port to avoid conflicts with any existing connections on fixed ports
            src_port = random.randint(1024, 65535)

            packet = (
                self._IP(dst=target) /
                self._TCP(sport=src_port, dport=port, flags="S")
            )

            response = self._sr1(packet, timeout=self.timeout)

            return self._interpret_response(response, target, port)

        except PermissionError:
            logger.error(
                "Permission denied on %s:%d - "
                "SYN scan requires Administrator privileges",
                target, port,
            )
            return PortState.FILTERED

        except Exception as e:
            logger.debug("SYN probe error on %s:%d - %s", target, port, e)
            return PortState.FILTERED

    def _interpret_response(self, response, target: str, port: int) -> PortState:
        """
        Parse the TCP flags in the response packet and map to a PortState.
        Isolated for testability - takes a response object, returns a state.
        """
        if response is None:
            # No response - firewall silently dropped it
            logger.debug("No response from %s:%d - FILTERED", target, port)
            return PortState.FILTERED

        # Check if this is a TCP response
        if response.haslayer(self._TCP):
            flags = response[self._TCP].flags

            if flags == TCP_SYN_ACK:
                # Send RST to cleanly close - don't leave half-open connections
                self._send_rst(target, port, response)
                logger.debug("SYN+ACK from %s:%d - OPEN", target, port)
                return PortState.OPEN

            if flags & TCP_RST:
                logger.debug("RST from %s:%d - CLOSED", target, port)
                return PortState.CLOSED

        # ICMP unreachable - firewall explicitly rejecting
        try:
            from scapy.all import ICMP
            if response.haslayer(ICMP):
                logger.debug("ICMP unreachable from %s:%d - FILTERED", target, port)
                return PortState.FILTERED
        except ImportError:
            pass

        return PortState.FILTERED

    def _send_rst(self, target: str, port: int, syn_ack_response) -> None:
        """
        Send a RST packet to cleanly terminate the half-open connection.
        This is good citizenship - don't leave half-open connections on targets.
        """
        try:
            from scapy.all import send
            rst = (
                self._IP(dst=target) /
                self._TCP(
                    sport = syn_ack_response[self._TCP].dport,
                    dport = port,
                    flags = "R",
                    seq   = syn_ack_response[self._TCP].ack,
                )
            )
            send(rst, verbose=0)
        except Exception as e:
            logger.debug("Failed to send RST to %s:%d - %s", target, port, e)

    @staticmethod
    def _validate_environment() -> None:
        """
        Fail fast with a clear message if the environment isn't ready.
        Better to raise here than get a confusing error mid-scan.
        """
        if not _is_scapy_available():
            raise EnvironmentError(
                "scapy is not installed. "
                "Run: pip install scapy"
            )
        if not _has_root_privileges():
            raise EnvironmentError(
                "SYN scan requires Administrator privileges on Windows "
                "or root on Linux/Mac. "
                "Re-run your terminal as Administrator."
            )