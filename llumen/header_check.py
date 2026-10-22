"""HTTP security header fetching and grading.

Presence and basic strength of the standard defensive header set:
Strict-Transport-Security, Content-Security-Policy, X-Frame-Options
(or CSP ``frame-ancestors``), X-Content-Type-Options, Referrer-Policy,
and Permissions-Policy. Version disclosure via ``Server`` /
``X-Powered-By`` costs a few points. The rubric is intentionally
simple, documented, and deterministic — it is a triage signal, not a
substitute for a full web security audit.
"""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass, field

from .targets import Target

# Rubric (sums to 100)
POINTS = {
    "hsts": 20,
    "csp": 25,
    "framing": 15,
    "content_type": 10,
    "referrer": 10,
    "permissions": 10,
    "no_disclosure": 10,
}

STRONG_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}

HSTS_STRONG_AGE = 31_536_000  # one year


@dataclass
class HeaderResult:
    target: str
    ok: bool = False
    error: str | None = None
    scheme: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    score: int | None = None
    grade: str = ""
    findings: list[str] = field(default_factory=list)


def grade_for_score(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _parse_hsts(value: str) -> tuple[int | None, bool]:
    max_age = None
    include_sub = False
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                max_age = None
        elif part == "includesubdomains":
            include_sub = True
    return max_age, include_sub


def grade_headers(headers: dict[str, str]) -> tuple[int, list[str]]:
    """Grade a header dict (names must already be lower-cased)."""
    findings: list[str] = []
    score = 0

    # --- HSTS (only meaningful over HTTPS, graded on presence/strength)
    hsts = headers.get("strict-transport-security")
    if hsts:
        max_age, include_sub = _parse_hsts(hsts)
        if max_age is not None and max_age >= HSTS_STRONG_AGE and include_sub:
            score += POINTS["hsts"]
        elif max_age is not None and max_age > 0:
            score += POINTS["hsts"] // 2
            findings.append(
                "HSTS present but weak (max-age < 1 year or missing includeSubDomains)"
            )
        else:
            findings.append("HSTS present but max-age missing/invalid")
    else:
        findings.append("missing Strict-Transport-Security")

    # --- CSP
    csp = headers.get("content-security-policy", "")
    if csp:
        lowered = csp.lower()
        score += POINTS["csp"] // 2
        strong = True
        if "'unsafe-inline'" in lowered:
            findings.append("CSP allows 'unsafe-inline'")
            strong = False
        if "'unsafe-eval'" in lowered:
            findings.append("CSP allows 'unsafe-eval'")
            strong = False
        # Wildcard as a source in default-src / script-src
        for directive in lowered.split(";"):
            directive = directive.strip()
            if directive.startswith(("default-src", "script-src")):
                sources = directive.split()[1:]
                if "*" in sources:
                    findings.append("CSP uses wildcard source (*)")
                    strong = False
        if strong:
            score += POINTS["csp"] - POINTS["csp"] // 2
    else:
        findings.append("missing Content-Security-Policy")

    # --- Framing protection: X-Frame-Options or CSP frame-ancestors
    xfo = headers.get("x-frame-options", "").strip().upper()
    frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo in ("DENY", "SAMEORIGIN") or frame_ancestors:
        score += POINTS["framing"]
    elif xfo:
        score += POINTS["framing"] // 2
        findings.append(f"X-Frame-Options has unusual value: {xfo!r}")
    else:
        findings.append("missing framing protection (X-Frame-Options / frame-ancestors)")

    # --- X-Content-Type-Options
    xcto = headers.get("x-content-type-options", "").strip().lower()
    if xcto == "nosniff":
        score += POINTS["content_type"]
    elif xcto:
        findings.append(f"X-Content-Type-Options is not 'nosniff': {xcto!r}")
    else:
        findings.append("missing X-Content-Type-Options")

    # --- Referrer-Policy
    referrer = headers.get("referrer-policy", "").strip().lower()
    if referrer in STRONG_REFERRER:
        score += POINTS["referrer"]
    elif referrer:
        score += POINTS["referrer"] // 2
        findings.append(f"Referrer-Policy is permissive: {referrer!r}")
    else:
        findings.append("missing Referrer-Policy")

    # --- Permissions-Policy
    if headers.get("permissions-policy"):
        score += POINTS["permissions"]
    else:
        findings.append("missing Permissions-Policy")

    # --- Version disclosure
    disclosed = [
        name
        for name in ("server", "x-powered-by")
        if headers.get(name) and any(ch.isdigit() for ch in headers[name])
    ]
    if not disclosed:
        score += POINTS["no_disclosure"]
    else:
        findings.append(
            "version disclosure in header(s): " + ", ".join(disclosed)
        )

    return score, findings


def _request(host: str, port: int, scheme: str, method: str, timeout: float):
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            method,
            "/",
            headers={"User-Agent": "llumen/1.0", "Accept": "*/*"},
        )
        resp = conn.getresponse()
        # Deliberately do NOT read the body: only headers are graded.
        # Draining the body would let a hostile or broken server stall
        # the scan indefinitely (slow-drip / endless body); the socket
        # is simply closed in the finally block.
        raw_headers: dict[str, str] = {}
        for name, value in resp.getheaders():
            key = name.lower()
            # Repeated headers (notably CSP) combine per RFC 9110.
            raw_headers[key] = (
                f"{raw_headers[key]}, {value}" if key in raw_headers else value
            )
        return resp.status, raw_headers
    finally:
        conn.close()


def fetch_headers(target: Target, timeout: float = 3.0, scheme: str = "auto") -> HeaderResult:
    """Fetch and grade headers for one target. Never raises."""
    result = HeaderResult(target=str(target))
    if scheme == "auto":
        scheme = "https" if target.port == 443 else "http"
    result.scheme = scheme
    try:
        try:
            status, headers = _request(target.host, target.port, scheme, "HEAD", timeout)
            if status in (405, 501):  # HEAD unsupported -> retry with GET
                status, headers = _request(target.host, target.port, scheme, "GET", timeout)
        except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
            if scheme == "https":
                raise
            # Plain HTTP failed; the port might still speak TLS.
            status, headers = _request(target.host, target.port, "https", "HEAD", timeout)
            if status in (405, 501):
                status, headers = _request(target.host, target.port, "https", "GET", timeout)
            result.scheme = "https"
    except (http.client.HTTPException, OSError, ssl.SSLError) as exc:
        result.error = f"header fetch failed: {exc}"
        return result

    result.ok = True
    result.status = status
    result.headers = headers
    result.score, result.findings = grade_headers(headers)
    result.grade = grade_for_score(result.score)
    return result
