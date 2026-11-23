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
import threading
from dataclasses import dataclass, field

MAX_SAN_CHECKS = 20
DEFAULT_DNS_TIMEOUT = 3.0


@dataclass
class SanCheckResult:
    """Outcome of checking a certificate's SAN hostnames.

    ``hints`` are names that definitively do not resolve (possible
    dangling names). ``timed_out`` are names whose lookup exceeded the
    timeout — unknown, never reported as dangling, so a slow resolver
    cannot manufacture false takeover hints.
    """

    hints: list[str] = field(default_factory=list)
    timed_out: list[str] = field(default_factory=list)


def resolves(host: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> bool | None:
    """True when the name yields at least one A/AAAA answer, False when
    it definitively does not resolve, None when the lookup timed out.

    The stdlib resolver has no timeout knob, so the blocking
    ``getaddrinfo`` call runs in a daemon worker thread and is abandoned
    after ``timeout`` seconds. A timed-out worker may linger in the
    background, but it can never stall the scan — and because the
    thread is a daemon, it can never block process exit either.
    """
    outcome: list[bool] = []

    def _lookup() -> None:
        try:
            socket.getaddrinfo(host, None)
            outcome.append(True)
        except Exception:
            outcome.append(False)

    worker = threading.Thread(target=_lookup, daemon=True, name="llumen-dns")
    worker.start()
    worker.join(timeout=timeout)
    if worker.is_alive():
        return None
    return outcome[0] if outcome else False


def check_sans(
    sans: list[str], exclude: str, timeout: float = DEFAULT_DNS_TIMEOUT
) -> SanCheckResult:
    """Check SAN hostnames (excluding the target itself and wildcards).

    Returns definite non-resolvers as hints and timed-out lookups
    separately; a timed-out name is never flagged as dangling.
    """
    result = SanCheckResult()
    checked = 0
    for name in sans:
        name = name.strip().lower()
        if not name or name == exclude.lower() or name.startswith("*."):
            continue
        if checked >= MAX_SAN_CHECKS:
            break
        checked += 1
        outcome = resolves(name, timeout=timeout)
        if outcome is False:
            result.hints.append(name)
        elif outcome is None:
            result.timed_out.append(name)
    return result


def dangling_sans(
    sans: list[str], exclude: str, timeout: float = DEFAULT_DNS_TIMEOUT
) -> list[str]:
    """Return SAN hostnames (excluding the target itself and wildcards)
    that fail DNS resolution — potential dangling/takeover candidates.

    Convenience wrapper around :func:`check_sans` returning only the
    definite hints; timed-out lookups are dropped, not flagged.
    """
    return check_sans(sans, exclude, timeout=timeout).hints
