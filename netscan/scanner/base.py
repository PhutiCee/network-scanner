from abc import ABC, abstractmethod
from netscan.core.models import PortResult


class BaseScanner(ABC):
    """
    Abstract base class for all scanner implementations.

    Every scanner receives a target and a port, and returns
    a PortResult. Threading, timeouts, and orchestration are
    the engine's responsibility - not the scanner's.
    """

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    @abstractmethod
    def scan_port(self, target: str, port: int) -> PortResult:
        """
        Attempt to determine the state of a single port.
        Must return a PortResult. Must never raise - handle
        all exceptions internally and return FILTERED on failure.
        """
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(timeout={self.timeout})"