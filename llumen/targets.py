"""Target parsing and normalization.

Accepts bare hostnames, ``host:port``, and full ``http(s)://`` URLs
(paths, queries, and userinfo are discarded). Internationalized names
are converted to Punycode (IDNA) so that the TLS layer always receives
the ASCII form a certificate would carry. Malformed lines are rejected
with a human-readable reason instead of raising.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


@dataclass(frozen=True)
class Target:
    host: str  # ASCII (Punycode) hostname or IP literal
    port: int

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    def __str__(self) -> str:  # pragma: no cover - display helper
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


class TargetError(ValueError):
    """Raised when one input line cannot be turned into a Target."""


def parse_target(raw: str, default_port: int = 443) -> Target:
    """Parse one input token into a Target or raise TargetError."""
    text = raw.strip()
    if not text:
        raise TargetError("empty target")
    if any(ch.isspace() for ch in text):
        raise TargetError(f"whitespace inside target: {raw!r}")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise TargetError("control characters in target")

    host = text
    port = default_port

    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https"):
            raise TargetError(f"unsupported scheme: {parts.scheme!r}")
        if not parts.hostname:
            raise TargetError(f"no host in URL: {raw!r}")
        host = parts.hostname
        try:
            if parts.port is not None:
                port = parts.port
        except ValueError as exc:
            raise TargetError(f"bad port in URL: {raw!r}") from exc
    elif text.startswith("["):
        # Bracketed IPv6 literal, optionally [::1]:8443
        end = text.find("]")
        if end == -1:
            raise TargetError(f"unterminated '[' in target: {raw!r}")
        host, rest = text[1:end], text[end + 1 :]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise TargetError(f"bad suffix after ']': {raw!r}")
            port = int(rest[1:])
    elif text.count(":") == 1:
        maybe_host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            host, port = maybe_host, int(maybe_port)
        elif maybe_port == "":
            raise TargetError(f"missing port after ':': {raw!r}")
        # A single colon with a non-numeric tail is invalid; fall through
        # and let hostname/IP validation reject it below.
    elif text.count(":") > 1:
        # Bare IPv6 literal without brackets is ambiguous with host:port.
        try:
            ipaddress.IPv6Address(text)
            return Target(host=text.lower(), port=port)
        except ValueError as exc:
            raise TargetError(f"invalid target: {raw!r}") from exc

    if not (1 <= port <= 65535):
        raise TargetError(f"port out of range: {port}")

    host = host.strip().rstrip(".").lower()
    if not host:
        raise TargetError(f"no host in target: {raw!r}")

    # IP literal?
    try:
        ip = ipaddress.ip_address(host)
        return Target(host=str(ip), port=port)
    except ValueError:
        pass

    # IDN -> Punycode (IDNA 2003 via the built-in codec).
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise TargetError(f"invalid internationalized name: {raw!r}") from exc
    if not _HOSTNAME_RE.match(ascii_host):
        raise TargetError(f"invalid hostname: {raw!r}")
    return Target(host=ascii_host, port=port)


def load_targets(lines, default_port: int = 443):
    """Parse many lines.

    Returns ``(targets, errors)`` where errors is a list of
    ``(line_number, raw_text, reason)`` for rejected lines. Blank lines
    and ``#`` comments are skipped silently. Duplicates are removed,
    preserving first-seen order.
    """
    targets: list[Target] = []
    errors: list[tuple[int, str, str]] = []
    seen: set[Target] = set()
    for lineno, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            target = parse_target(stripped, default_port=default_port)
        except TargetError as exc:
            errors.append((lineno, stripped, str(exc)))
            continue
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return targets, errors
