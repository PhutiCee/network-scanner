import ipaddress
from netscan.utils.validators import ValidationError

def parse_port_expression(expr: str) -> list[int]:
    """
    Parse a port expression into a sorted list of integers.

    Supports:
        "80"          → [80]
        "80,443"      → [80, 443]
        "1-1024"      → [1, 2, ..., 1024]
        "22,80,443"   → [22, 80, 443]
        "1-100,443"   → [1..100, 443]
    """
    ports = set()

    for part in expr.split(","):
        part = part.strip()
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValidationError(f"Invalid port range: '{part}'")
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise ValidationError(f"Non-integer in range: '{part}'")
            if lo > hi:
                raise ValidationError(
                    f"Range start {lo} is greater than end {hi}"
                )
            ports.update(range(lo, hi + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValidationError(f"Not a valid port number: '{part}'")

    return sorted(ports)

def expand_cidr(cidr: str) -> list[str]:
    """
    Expand a CIDR block into individual IP address strings.
    Example: "192.168.1.0/30" → ["192.168.1.1", "192.168.1.2"]
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValidationError(str(e)) from e

    return [str(ip) for ip in network.hosts()]