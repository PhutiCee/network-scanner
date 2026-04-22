# netscan/core/engine.py

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable

from netscan.config import ScanConfig
from netscan.core.models import PortResult, ScanResult, ScanType
from netscan.output.logger import get_logger
from netscan.scanner.banner import identify_service
from netscan.scanner.base import BaseScanner
from netscan.scanner.tcp_connect import TCPConnectScanner

logger = get_logger(__name__)


class ScanEngine:
    """
    Orchestrates concurrent port scanning using ThreadPoolExecutor.

    Responsibilities:
      - Select the correct scanner based on ScanConfig.scan_type
      - Submit one task per port to the thread pool
      - Collect results safely as futures complete
      - Enrich results with service identification
      - Report progress via optional callback
      - Return a fully populated ScanResult

    Not responsible for:
      - How individual ports are scanned (delegated to scanner)
      - Output formatting (delegated to exporters)
      - Argument parsing (delegated to CLI)
    """

    def __init__(self, config: ScanConfig):
        self.config  = config
        self.scanner = self._build_scanner()
        self._lock   = threading.Lock()   # guards any shared state mutations
        self._stop   = threading.Event()  # allows graceful cancellation

    # Public API

    def run(
        self,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> ScanResult:
        """
        Execute the scan and return a populated ScanResult.

        Args:
            progress_callback: Optional callable(completed, total) called
                               after each port finishes. Used by CLI to
                               render a progress bar.
        """
        config = self.config
        result = ScanResult(
            target    = config.target,
            scan_type = config.scan_type,
        )

        total     = len(config.ports)
        completed = 0

        logger.info(
            "Starting %s scan on %s — %d ports, %d threads",
            config.scan_type.value,
            config.target,
            total,
            config.threads,
        )

        with ThreadPoolExecutor(max_workers=config.threads) as executor:
            # Submit all port scans as futures
            future_to_port = {
                executor.submit(self._scan_one, config.target, port): port
                for port in config.ports
            }

            for future in as_completed(future_to_port):
                if self._stop.is_set():
                    logger.warning("Scan cancelled — stopping early")
                    break

                port = future_to_port[future]

                try:
                    port_result = future.result()
                except Exception as e:
                    # This should not happen — _scan_one catches internally.
                    # Defensive catch so one bad future never kills the run.
                    logger.error(
                        "Unexpected error on port %d: %s", port, e
                    )
                    continue

                with self._lock:
                    result.ports.append(port_result)
                    completed += 1

                if progress_callback:
                    progress_callback(completed, total)

                if port_result.is_open():
                    logger.info(
                        "Open port found: %s:%d (%s)",
                        config.target,
                        port_result.port,
                        port_result.service or "unknown",
                    )

        result.ended_at = datetime.utcnow()
        result.ports.sort(key=lambda p: p.port)  # always return sorted

        logger.info(
            "Scan complete — %d open of %d scanned in %.2fs",
            len(result.open_ports()),
            total,
            result.duration_seconds(),
        )

        return result

    def cancel(self) -> None:
        """Signal the engine to stop after the current batch completes."""
        self._stop.set()
        logger.warning("Cancellation requested")

    # Private helpers 

    def _scan_one(self, target: str, port: int) -> PortResult:
        """
        Scan a single port and enrich the result with service info.
        This method runs inside a worker thread.
        """
        port_result = self.scanner.scan_port(target, port)

        # Enrich with service identification regardless of banner
        port_result.service = identify_service(port, port_result.banner)

        logger.debug(
            "%s:%d → %s (%s) in %.1fms",
            target,
            port,
            port_result.state.value,
            port_result.service or "unknown",
            port_result.scan_time_ms,
        )

        return port_result

    def _build_scanner(self) -> BaseScanner:
        config = self.config

        if config.scan_type == ScanType.TCP_CONNECT:
            return TCPConnectScanner(
                timeout     = config.timeout,
                grab_banner = config.grab_banner,
            )

        if config.scan_type == ScanType.SYN:
            try:
                from netscan.scanner.syn_scan import SYNScanner
                return SYNScanner(timeout=config.timeout)
            except (ImportError, EnvironmentError) as e:
                logger.warning(
                    "SYN scan unavailable: %s — falling back to TCP connect", e
                )
                return TCPConnectScanner(
                    timeout     = config.timeout,
                    grab_banner = config.grab_banner,
                )

        raise NotImplementedError(
            f"No scanner implemented for '{config.scan_type.value}'"
        )