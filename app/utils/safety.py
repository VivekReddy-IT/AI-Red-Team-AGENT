import ipaddress
import socket
from urllib.parse import urlparse


ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "testphp.vulnweb.com",
    "scanme.nmap.org",
}


def _extract_host(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        return host.strip().lower()
    return target.strip().lower().split("/")[0]


def _is_loopback_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


def validate_target_safe_mode(target: str) -> tuple[bool, str]:
    """
    Safe mode policy:
    - Allow explicit host allowlist
    - Allow localhost/loopback
    - Reject all other public hosts by default
    """
    host = _extract_host(target)
    if not host:
        return False, "Target is empty or invalid."

    if host in ALLOWED_HOSTS or _is_loopback_ip(host):
        return True, host

    # Resolve host and allow only if it resolves to loopback.
    try:
        resolved_ip = socket.gethostbyname(host)
        if ipaddress.ip_address(resolved_ip).is_loopback:
            return True, host
    except Exception:
        pass

    return (
        False,
        "Target rejected by safe mode. Use localhost or approved test hosts only.",
    )
