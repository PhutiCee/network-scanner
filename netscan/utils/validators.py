import ipaddress
import re

class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


def validate_target(target: str) -> str:
    """
    Accept an IPv4 address, IPv6 address, or hostname.
    Returns the target unchanged if valid, raises ValidationError otherwise.
    """
    target = target.strip()

    # Try as an IP address first
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Try as a CIDR range
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    # Basic hostname validation (RFC 1123)
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if hostname_re.match(target):
        return target

    raise ValidationError(f"Invalid target: '{target}'. "
                          f"Must be an IP, CIDR range, or hostname.")

def validate_ports(ports: list[int]) -> list[int]:
    """Ensure all ports are in the valid range 1–65535."""
    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        raise ValidationError(
            f"Invalid port(s): {invalid}. Ports must be between 1 and 65535."
        )
    return sorted(set(ports))  # deduplicate and sort

def validate_threads(n: int) -> int:
    if not (1 <= n <= 500):
        raise ValidationError(
            f"Thread count {n} is out of range. Use 1–500."
        )
    return n

def validate_timeout(t: float) -> float:
    if not (0.1 <= t <= 30.0):
        raise ValidationError(
            f"Timeout {t}s is out of range. Use 0.1–30.0 seconds."
        )
    return t