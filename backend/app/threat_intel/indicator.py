"""Indicator classification, validation, and SSRF-aware extraction."""

from enum import Enum
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
HASH_MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
HASH_SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
HASH_SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

BLOCKED_INTERNAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
}


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    HASH = "hash"
    UNKNOWN = "unknown"


def is_valid_ipv4(val: str) -> bool:
    try:
        ipaddress.IPv4Address(val.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(val: str) -> bool:
    try:
        ipaddress.IPv6Address(val.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_domain(val: str) -> bool:
    val = val.strip().lower()
    if len(val) > 253 or not val:
        return False
    return bool(DOMAIN_REGEX.match(val))


def is_valid_url(val: str) -> bool:
    val = val.strip()
    if not (val.startswith("http://") or val.startswith("https://")):
        return False
    try:
        parsed = urlparse(val)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        # Prevent javascript:, data:, file:, etc.
        return True
    except Exception:
        return False


def is_valid_md5(val: str) -> bool:
    val = val.strip()
    return bool(HASH_MD5_REGEX.match(val))


def is_valid_sha1(val: str) -> bool:
    val = val.strip()
    return bool(HASH_SHA1_REGEX.match(val))


def is_valid_sha256(val: str) -> bool:
    val = val.strip()
    return bool(HASH_SHA256_REGEX.match(val))


def is_valid_hash(val: str) -> bool:
    val = val.strip()
    return is_valid_md5(val) or is_valid_sha1(val) or is_valid_sha256(val)


def get_specific_hash_type(indicator: str) -> Optional[IndicatorType]:
    """Identify specific hash algorithm if string is a valid cryptographic digest."""
    ind = indicator.strip()
    if is_valid_md5(ind):
        return IndicatorType.MD5
    if is_valid_sha1(ind):
        return IndicatorType.SHA1
    if is_valid_sha256(ind):
        return IndicatorType.SHA256
    return None


def classify_indicator(indicator: str) -> IndicatorType:
    """Classify the type of threat intelligence indicator."""
    ind = indicator.strip()
    if is_valid_ipv4(ind):
        return IndicatorType.IPV4
    if is_valid_ipv6(ind):
        return IndicatorType.IPV6
    if is_valid_url(ind):
        return IndicatorType.URL
    if is_valid_hash(ind):
        return IndicatorType.HASH
    if is_valid_domain(ind):
        return IndicatorType.DOMAIN
    return IndicatorType.UNKNOWN


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP address is an internal private, loopback, or link-local address (SSRF safety)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def is_ssrf_risk(indicator: str, indicator_type: str) -> bool:
    """Determine if querying external providers with this indicator poses an SSRF or internal leak risk."""
    ind = indicator.strip().lower()
    if indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6, "ipv4", "ipv6", "ip"):
        return is_private_or_reserved_ip(ind)

    if indicator_type in (IndicatorType.DOMAIN, "domain"):
        if ind in BLOCKED_INTERNAL_HOSTS or ind.endswith(".local") or ind.endswith(".internal"):
            return True
        return False

    if indicator_type in (IndicatorType.URL, "url"):
        try:
            parsed = urlparse(ind)
            host = (parsed.hostname or "").lower()
            if host in BLOCKED_INTERNAL_HOSTS or is_private_or_reserved_ip(host):
                return True
            if parsed.scheme not in ("http", "https"):
                return True
        except Exception:
            return True

    return False


def validate_indicator(indicator: str, expected_type: Optional[str] = None) -> Tuple[bool, str, str]:
    """Strictly validate and canonicalize an indicator.
    
    Returns (is_valid, canonical_indicator, indicator_type).
    """
    if not indicator or not isinstance(indicator, str):
        return False, "", IndicatorType.UNKNOWN.value

    ind = indicator.strip()
    # Strip protocol if domain query accidentally passed with http://
    if expected_type in ("domain", IndicatorType.DOMAIN.value) and ind.startswith(("http://", "https://")):
        try:
            parsed = urlparse(ind)
            ind = parsed.netloc or ind
        except Exception:
            pass

    detected_type = classify_indicator(ind)

    if expected_type:
        exp = expected_type.lower()
        if exp == "ip" and detected_type in (IndicatorType.IPV4, IndicatorType.IPV6):
            return True, ind, detected_type.value
        if exp in ("hash", IndicatorType.HASH.value) and is_valid_hash(ind):
            return True, ind.lower(), IndicatorType.HASH.value
        specific_hash = get_specific_hash_type(ind)
        if specific_hash and exp == specific_hash.value:
            return True, ind.lower(), specific_hash.value
        if exp == detected_type.value:
            canonical = ind.lower() if detected_type in (IndicatorType.DOMAIN, IndicatorType.HASH) else ind
            return True, canonical, detected_type.value
        return False, ind, IndicatorType.UNKNOWN.value

    if detected_type != IndicatorType.UNKNOWN:
        canonical = ind.lower() if detected_type in (IndicatorType.DOMAIN, IndicatorType.HASH) else ind
        return True, canonical, detected_type.value

    return False, ind, IndicatorType.UNKNOWN.value


def extract_indicators(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract all valid threat indicators (IPs, domains, hashes, URLs) from an event."""
    results: List[Dict[str, str]] = []
    seen = set()

    def add_if_valid(val: Optional[str], preferred_type: Optional[str] = None):
        if not val or not isinstance(val, str):
            return
        clean_val = val.strip()
        if clean_val.lower() in seen or len(clean_val) < 3:
            return
        is_valid, canonical, ind_type = validate_indicator(clean_val, preferred_type)
        if is_valid and ind_type != IndicatorType.UNKNOWN.value:
            seen.add(canonical.lower())
            results.append({
                "indicator": canonical,
                "indicator_type": ind_type,
            })

    # Source & destination IPs
    add_if_valid(event.get("source_ip"), "ip")
    add_if_valid(event.get("destination_ip"), "ip")

    # Explicit domain or hostname (if domain)
    if event.get("domain"):
        add_if_valid(event.get("domain"), "domain")
    hostname = event.get("hostname")
    if hostname and ("." in hostname or hostname.endswith(".internal") or hostname.endswith(".lab") or hostname.endswith(".test")):
        add_if_valid(hostname, "domain")

    # Explicit URL or file hash
    if event.get("url"):
        add_if_valid(event.get("url"), "url")
    for hash_key in ("file_hash", "hash", "md5", "sha1", "sha256"):
        if event.get(hash_key):
            add_if_valid(event.get(hash_key), "hash")

    # Command line and message parsing for URLs and hashes
    raw_text = f"{event.get('command_line') or ''} {event.get('message') or ''}"

    # Extract SHA256 / SHA1 / MD5 hashes and URLs
    for word in raw_text.split():
        clean_word = word.strip(" '\",;()[]{}")
        if is_valid_hash(clean_word):
            add_if_valid(clean_word, "hash")
        elif clean_word.startswith(("http://", "https://")) and is_valid_url(clean_word):
            add_if_valid(clean_word, "url")

    return results
