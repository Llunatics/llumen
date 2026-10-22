"""TLS certificate probing.

The probe always runs with an *unverified* SSL context first, so that
self-signed, expired, or otherwise broken certificates still yield their
data instead of aborting the scan. Validation is then attempted as a
separate, verified handshake whose outcome is reported independently —
never conflated with extraction.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .targets import Target

WARN_EXPIRED = "certificate has expired"
WARN_EXPIRING_30 = "expires in less than 30 days"
WARN_EXPIRING_7 = "expires in less than 7 days"


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    not_before: str = ""  # ISO 8601, UTC
    not_after: str = ""  # ISO 8601, UTC
    days_left: int | None = None
    serial: str = ""
    fingerprint_sha256: str = ""
    signature_algorithm: str = ""


@dataclass
class TlsResult:
    target: str
    ok: bool = False
    error: str | None = None
    tls_version: str = ""
    cipher: str = ""
    cipher_bits: int | None = None
    cert: CertInfo | None = None
    validation: str = "not-checked"  # "valid" or a failure description
    warnings: list[str] = field(default_factory=list)


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _format_dn(attrs) -> str:
    parts = []
    for attr in attrs:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def _parse_with_cryptography(der: bytes) -> CertInfo:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID  # noqa: F401

    cert = x509.load_der_x509_certificate(der)
    info = CertInfo()
    info.subject = _format_dn(cert.subject)
    info.issuer = _format_dn(cert.issuer)
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        info.sans = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        info.sans = []
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older cryptography without *_utc properties
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    info.not_before = not_before.astimezone(timezone.utc).isoformat()
    info.not_after = not_after.astimezone(timezone.utc).isoformat()
    info.days_left = (not_after - datetime.now(timezone.utc)).days
    info.serial = format(cert.serial_number, "x")
    info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex(":")
    try:
        info.signature_algorithm = cert.signature_algorithm_oid._name
    except Exception:
        info.signature_algorithm = ""
    return info


def _parse_with_stdlib(der: bytes) -> CertInfo:
    """Fallback parser using CPython's private test decoder."""
    info = CertInfo()
    hexfp = hashlib.sha256(der).hexdigest()
    info.fingerprint_sha256 = ":".join(
        hexfp[i : i + 2] for i in range(0, len(hexfp), 2)
    )
    with tempfile.NamedTemporaryFile(suffix=".der", delete=True) as fh:
        fh.write(der)
        fh.flush()
        decoded = ssl._ssl._test_decode_cert(fh.name)  # noqa: SLF001
    info.subject = ", ".join(
        f"{k}={v}" for rdn in decoded.get("subject", ()) for k, v in rdn
    )
    info.issuer = ", ".join(
        f"{k}={v}" for rdn in decoded.get("issuer", ()) for k, v in rdn
    )
    info.sans = [v for kind, v in decoded.get("subjectAltName", ()) if kind == "DNS"]
    info.serial = str(decoded.get("serialNumber", ""))
    for key, attr in (("notBefore", "not_before"), ("notAfter", "not_after")):
        raw = decoded.get(key)
        if raw:
            dt = ssl.cert_time_to_seconds(raw)
            iso = datetime.fromtimestamp(dt, tz=timezone.utc).isoformat()
            setattr(info, attr, iso)
    if info.not_after:
        not_after = datetime.fromisoformat(info.not_after)
        info.days_left = (not_after - datetime.now(timezone.utc)).days
    return info


def parse_certificate(der: bytes) -> CertInfo:
    """Parse DER certificate bytes into a CertInfo."""
    try:
        return _parse_with_cryptography(der)
    except ImportError:
        return _parse_with_stdlib(der)


def expiry_warnings(cert: CertInfo) -> list[str]:
    if cert.days_left is None:
        return []
    if cert.days_left < 0:
        return [WARN_EXPIRED]
    if cert.days_left < 7:
        return [WARN_EXPIRING_7]
    if cert.days_left < 30:
        return [WARN_EXPIRING_30]
    return []


def _describe_error(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return f"DNS resolution failed: {exc}"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc}"
    if isinstance(exc, OSError):
        return f"network error: {exc}"
    return f"{type(exc).__name__}: {exc}"


def _validate(host: str, port: int, timeout: float, is_ip: bool) -> str:
    """Attempt a fully verified handshake; return the outcome as text."""
    ctx = ssl.create_default_context()
    if is_ip:
        # Default context cannot hostname-check an IP literal reliably
        # across versions; chain verification still applies.
        ctx.check_hostname = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None if is_ip else host):
                return "valid"
    except ssl.SSLCertVerificationError as exc:
        return f"invalid: {exc.verify_message}"
    except (OSError, ssl.SSLError) as exc:
        return f"unreachable during validation: {_describe_error(exc)}"


def probe_tls(target: Target, timeout: float = 3.0) -> TlsResult:
    """Probe one target. Never raises for network problems."""
    result = TlsResult(target=str(target))
    host, port = target.host, target.port
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            ctx = _unverified_context()
            with ctx.wrap_socket(
                raw, server_hostname=None if target.is_ip else host
            ) as tls:
                result.tls_version = tls.version() or ""
                cipher = tls.cipher()
                if cipher:
                    result.cipher = cipher[0]
                    result.cipher_bits = cipher[2]
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as exc:
        result.error = _describe_error(exc)
        return result

    if not der:
        result.error = "server presented no certificate"
        return result

    try:
        result.cert = parse_certificate(der)
    except Exception as exc:  # malformed certificate bytes
        result.error = f"could not parse certificate: {exc}"
        return result

    result.ok = True
    result.warnings = expiry_warnings(result.cert)
    result.validation = _validate(host, port, timeout, target.is_ip)
    return result
