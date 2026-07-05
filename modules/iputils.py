"""
IP utilities — family-neutral (IPv4 + IPv6) helpers shared by the detection
and response engines.

Historically the source-IP patterns lived in two copies (detection_engine and
response_engine) and only matched IPv4. Centralising them here keeps the two
engines in sync and closes the IPv6 blind spot: a brute force arriving over
IPv6 is now grouped per source and blockable like its IPv4 counterpart.

Security note (see docs/SECURITY_AUDIT.md, LS-01): extract_source_ips() only
reads structured source-address fields; it must stay the ONLY source of
blocking candidates. extract_all_ips() scans free text and is safe for
read-only uses such as threat-intel lookups.
"""

import ipaddress
import re
from typing import List, Optional

# Candidate tokens: runs of hex digits, dots and colons. Deliberately loose —
# every candidate is validated with ipaddress before being accepted, so noise
# like timestamps ("10:30:00") or words ("Time:") is rejected cheaply.
_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:.]+")

# Structured source-address fields (the only trusted origin for blocking):
# Windows 'Source Network Address:', Linux PAM 'rhost=', SSH 'from <ip>'.
_SOURCE_FIELD_PATTERNS = [
    re.compile(r"Source Network Address:\s*([0-9A-Fa-f:.]+)", re.IGNORECASE),
    re.compile(r"rhost=([0-9A-Fa-f:.]+)", re.IGNORECASE),
    re.compile(r"\bfrom\s+([0-9A-Fa-f:.]+)", re.IGNORECASE),
]


def normalize_ip(candidate: str) -> Optional[str]:
    """
    Return the canonical (compressed) form of an IPv4/IPv6 address, or None if
    the string is not a valid address. Trailing punctuation picked up by the
    loose token regex (e.g. a sentence-ending dot) is stripped before parsing.
    Canonicalising matters for IPv6, where '2001:DB8::1' and '2001:0db8:0:0::1'
    are the same address and must compare equal in allowlists and feeds.
    """
    if not candidate:
        return None
    token = candidate.strip()
    # Try the raw token first so addresses that legitimately end in '::'
    # (e.g. '2001:db8::') survive; only then strip trailing punctuation.
    for cand in (token, token.rstrip(".:")):
        if not cand:
            continue
        try:
            return ipaddress.ip_address(cand).compressed
        except ValueError:
            pass
    return None


def is_valid_ip(candidate: str) -> bool:
    """True if the string is a valid IPv4 or IPv6 address."""
    return normalize_ip(candidate) is not None


def is_private_ip(candidate: str) -> bool:
    """
    True if the address is private, loopback or link-local (either family).
    Invalid addresses return False.
    """
    normalized = normalize_ip(candidate or "")
    if normalized is None:
        return False
    ip = ipaddress.ip_address(normalized)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def extract_all_ips(text: str) -> List[str]:
    """
    Extract every valid IPv4/IPv6 address found anywhere in the text,
    normalized and de-duplicated, in order of first appearance.

    Positions are NOT trusted — never use this to pick blocking targets
    (an attacker can plant an IP in a username; see extract_source_ips).
    """
    if not text:
        return []
    found: List[str] = []
    for token in _CANDIDATE_RE.findall(text):
        # Require a separator so bare numbers ("2026") are never treated as
        # candidate addresses (ipaddress accepts int-like strings).
        if "." not in token and ":" not in token:
            continue
        ip = normalize_ip(token)
        if ip and ip not in found:
            found.append(ip)
    return found


def extract_source_ips(text: str) -> List[str]:
    """
    Extract only IPs appearing in structured SOURCE-ADDRESS fields, normalized
    and de-duplicated, in order of first appearance.

    This is the only safe origin for blocking candidates: a generic scan would
    also pick up IPs embedded in attacker-controlled strings (usernames,
    workstation names), letting an attacker trick the auto-response into
    blocking arbitrary third-party addresses (LS-01).
    """
    if not text:
        return []
    found: List[str] = []
    for pattern in _SOURCE_FIELD_PATTERNS:
        for match in pattern.findall(text):
            ip = normalize_ip(match)
            if ip and ip not in found:
                found.append(ip)
    return found
