"""Passive subdomain-takeover hints.

The only signal used here is negative DNS evidence: a hostname that
appears in a certificate's SAN list but no longer resolves at all is a
*dangling* name — if it is (or was) pointed at a third-party service by
a CNAME, it may be claimable by someone else. llumen reports this as a
hint for manual verification only. It performs no CNAME chasing, no
fingerprinting of third-party services, and no active enumeration.
"""

from __future__ import annotations

import socket

MAX_SAN_CHECKS = 20


def resolves(host: str) -> bool:
    """True when the name yields at least one A/AAAA answer."""
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        return False


def dangling_sans(sans: list[str], exclude: str) -> list[str]:
    """Return SAN hostnames (excluding the target itself and wildcards)
    that fail DNS resolution — potential dangling/takeover candidates."""
    hints: list[str] = []
    checked = 0
    for name in sans:
        name = name.strip().lower()
        if not name or name == exclude.lower() or name.startswith("*."):
            continue
        if checked >= MAX_SAN_CHECKS:
            break
        checked += 1
        if not resolves(name):
            hints.append(name)
    return hints
