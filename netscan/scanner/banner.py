import re

# Ordered list of (pattern, service_name) tuples.
# First match wins — order from most specific to least specific.
BANNER_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^SSH-",              re.I), "ssh"),
    (re.compile(r"^220.*FTP",          re.I), "ftp"),
    (re.compile(r"^220.*SMTP|ESMTP",   re.I), "smtp"),
    (re.compile(r"^HTTP/",             re.I), "http"),
    (re.compile(r"^\+OK",              re.I), "pop3"),
    (re.compile(r"^\* OK.*IMAP",       re.I), "imap"),
    (re.compile(r"^220.*Telnet",       re.I), "telnet"),
    (re.compile(r"mysql_native",       re.I), "mysql"),
    (re.compile(r"PostgreSQL",         re.I), "postgresql"),
    (re.compile(r"Redis",              re.I), "redis"),
    (re.compile(r"MongoDB",            re.I), "mongodb"),
]

# Well-known port -> service name fallback (when banner is absent)
WELL_KNOWN_PORTS: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    135:   "msrpc",
    139:   "netbios",
    143:   "imap",
    443:   "https",
    445:   "smb",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    6379:  "redis",
    8080:  "http-alt",
    8443:  "https-alt",
    27017: "mongodb",
}


def identify_service(port: int, banner: str) -> str:
    """
    Identify the service running on a port.

    Strategy:
      1. Try banner matching (most accurate)
      2. Fall back to well-known port lookup
      3. Return empty string if unknown
    """
    if banner:
        for pattern, service in BANNER_SIGNATURES:
            if pattern.search(banner):
                return service

    return WELL_KNOWN_PORTS.get(port, "")