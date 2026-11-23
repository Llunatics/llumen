"""Offline test suite for llumen.

Everything runs against local servers on 127.0.0.1 with certificates
minted in-process (valid self-signed, and expired). No external network
is required.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from llumen import cli
from llumen.dns_check import check_sans, dangling_sans, resolves
from llumen.header_check import fetch_headers, grade_for_score, grade_headers
from llumen.targets import Target, TargetError, load_targets, parse_target
from llumen.tls_probe import parse_certificate, probe_tls

FULL_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
    "Server": "nginx",
}

# For live servers, the Server header comes from the handler's
# server_version/sys_version (send_response adds it automatically).
FULL_PROFILE = {k: v for k, v in FULL_HEADERS.items() if k != "Server"}
NO_PROFILE = {}


def mint_cert(cn, sans, not_before, not_after, key, ip_sans=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans or ip_sans:
        names = [x509.DNSName(s) for s in (sans or [])]
        names += [
            x509.IPAddress(ipaddress.ip_address(ip)) for ip in (ip_sans or [])
        ]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def write_pem(path: Path, cert, key):
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    path.write_bytes(cert_pem + key_pem)
    return cert


class HeaderHandler(BaseHTTPRequestHandler):
    profile = FULL_HEADERS
    head_405 = False

    def _send(self):
        self.send_response(200)
        for name, value in self.profile.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b"ok")

    do_GET = _send

    def do_HEAD(self):
        if type(self).head_405:
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send()

    def log_message(self, *args):  # silence
        pass


class RedirectHandler(BaseHTTPRequestHandler):
    redirect_map = {}  # path -> (status, location)
    final_profile = FULL_PROFILE

    def _handle(self):
        route = self.redirect_map.get(self.path)
        if route is not None:
            status, location = route
            self.send_response(status)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        for name, value in self.final_profile.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b"ok")

    do_GET = _handle
    do_HEAD = _handle

    def log_message(self, *args):  # silence
        pass


def make_server(handler_cls, certfile=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class FixtureBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="llumen-test-"))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        cls.cert_valid = write_pem(
            cls.tmp / "valid.pem",
            mint_cert(
                "localhost",
                ["localhost", "example.test", "dangling.test"],
                now - timedelta(days=1),
                now + timedelta(days=90),
                key,
            ),
            key,
        )
        cls.cert_expired = write_pem(
            cls.tmp / "expired.pem",
            mint_cert(
                "localhost",
                ["localhost"],
                now - timedelta(days=10),
                now - timedelta(days=1),
                key,
            ),
            key,
        )
        cls.cert_ip = write_pem(
            cls.tmp / "ip.pem",
            mint_cert(
                "localhost",
                ["localhost"],
                now - timedelta(days=1),
                now + timedelta(days=90),
                key,
                ip_sans=["127.0.0.1"],
            ),
            key,
        )

        full = type(
            "Full",
            (HeaderHandler,),
            {"profile": FULL_PROFILE, "server_version": "nginx", "sys_version": ""},
        )
        bare = type(
            "Bare",
            (HeaderHandler,),
            {
                "profile": NO_PROFILE,
                "server_version": "Apache/2.4.41",
                "sys_version": "(Ubuntu)",
            },
        )
        head405 = type(
            "Head405",
            (HeaderHandler,),
            {
                "profile": FULL_PROFILE,
                "head_405": True,
                "server_version": "nginx",
                "sys_version": "",
            },
        )
        cls.https_full = make_server(full, cls.tmp / "valid.pem")
        cls.https_bare_expired = make_server(bare, cls.tmp / "expired.pem")
        cls.http_head405 = make_server(head405)
        cls.port_tls = cls.https_full.server_address[1]
        cls.port_expired = cls.https_bare_expired.server_address[1]
        cls.port_http = cls.http_head405.server_address[1]

        ip_san = type(
            "IpSan",
            (HeaderHandler,),
            {"profile": FULL_PROFILE, "server_version": "nginx", "sys_version": ""},
        )
        cls.https_ip_san = make_server(ip_san, cls.tmp / "ip.pem")
        cls.port_ip = cls.https_ip_san.server_address[1]

        redirect_rel = type(
            "RedirectRel",
            (RedirectHandler,),
            {
                "redirect_map": {"/": (301, "/final")},
                "final_profile": FULL_PROFILE,
                "server_version": "nginx",
                "sys_version": "",
            },
        )
        redirect_loop = type(
            "RedirectLoop",
            (RedirectHandler,),
            {
                "redirect_map": {"/": (302, "/")},
                "final_profile": FULL_PROFILE,
                "server_version": "nginx",
                "sys_version": "",
            },
        )
        redirect_chain = type(
            "RedirectChain",
            (RedirectHandler,),
            {
                "redirect_map": {
                    "/": (302, "/c1"),
                    "/c1": (302, "/c2"),
                    "/c2": (302, "/c3"),
                    "/c3": (302, "/c4"),
                    "/c4": (302, "/c5"),
                    "/c5": (302, "/c6"),
                    "/c6": (302, "/final"),
                },
                "final_profile": FULL_PROFILE,
                "server_version": "nginx",
                "sys_version": "",
            },
        )
        redirect_to_tls = type(
            "RedirectToTls",
            (RedirectHandler,),
            {
                "redirect_map": {"/": (302, f"https://127.0.0.1:{cls.port_tls}/")},
                "final_profile": FULL_PROFILE,
                "server_version": "nginx",
                "sys_version": "",
            },
        )
        cls.http_redirect_rel = make_server(redirect_rel)
        cls.http_redirect_loop = make_server(redirect_loop)
        cls.http_redirect_chain = make_server(redirect_chain)
        cls.http_redirect_to_tls = make_server(redirect_to_tls)
        cls.port_redirect_rel = cls.http_redirect_rel.server_address[1]
        cls.port_redirect_loop = cls.http_redirect_loop.server_address[1]
        cls.port_redirect_chain = cls.http_redirect_chain.server_address[1]
        cls.port_redirect_to_tls = cls.http_redirect_to_tls.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for srv in (
            cls.https_full,
            cls.https_bare_expired,
            cls.http_head405,
            cls.https_ip_san,
            cls.http_redirect_rel,
            cls.http_redirect_loop,
            cls.http_redirect_chain,
            cls.http_redirect_to_tls,
        ):
            srv.shutdown()


# ---------------------------------------------------------------- targets


class TestTargets(unittest.TestCase):
    def test_bare_hostname(self):
        t = parse_target("Example.COM.")
        self.assertEqual(t, Target("example.com", 443))

    def test_host_port(self):
        self.assertEqual(parse_target("example.com:8443"), Target("example.com", 8443))

    def test_url_with_path_and_userinfo(self):
        t = parse_target("https://user:secret@example.com:8443/a/b?x=1")
        self.assertEqual(t, Target("example.com", 8443))

    def test_http_url_default_port_kept(self):
        self.assertEqual(parse_target("http://example.com/page"), Target("example.com", 443))

    def test_idn_to_punycode(self):
        self.assertEqual(parse_target("bücher.de").host, "xn--bcher-kva.de")

    def test_ipv4_literal(self):
        t = parse_target("192.0.2.10:8080")
        self.assertEqual(t, Target("192.0.2.10", 8080))
        self.assertTrue(t.is_ip)

    def test_bracketed_ipv6(self):
        t = parse_target("[::1]:8443")
        self.assertEqual(t, Target("::1", 8443))
        self.assertTrue(t.is_ip)

    def test_bare_ipv6(self):
        self.assertEqual(parse_target("::1"), Target("::1", 443))

    def test_rejects_garbage(self):
        for raw in (
            "",
            "exa mple.com",
            "example.com:",
            "example.com:99999",
            "example.com:0",
            "ftp://example.com",
            "-bad-.com",
            "http://",
            "exa\x01mple.com",
            "[::1",
            "example.com:abc:def",
        ):
            with self.assertRaises(TargetError, msg=raw):
                parse_target(raw)

    def test_load_targets_skips_comments_and_dedupes(self):
        targets, errors = load_targets(
            ["# comment", "", "example.com", "example.com", "bad host", "a.com:81"]
        )
        self.assertEqual(targets, [Target("example.com", 443), Target("a.com", 81)])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][0], 5)  # 1-based line number


# ------------------------------------------------------------- cert parse


class TestCertParse(FixtureBase):
    def test_parse_valid_cert(self):
        der = self.cert_valid.public_bytes(serialization.Encoding.DER)
        info = parse_certificate(der)
        self.assertIn("localhost", info.sans)
        self.assertIn("dangling.test", info.sans)
        self.assertTrue(85 <= info.days_left <= 90)
        self.assertIn(":", info.fingerprint_sha256)
        self.assertTrue(info.signature_algorithm)

    def test_parse_expired_cert(self):
        der = self.cert_expired.public_bytes(serialization.Encoding.DER)
        info = parse_certificate(der)
        self.assertLess(info.days_left, 0)

    def test_parse_ip_sans(self):
        der = self.cert_ip.public_bytes(serialization.Encoding.DER)
        info = parse_certificate(der)
        self.assertEqual(info.ip_sans, ["127.0.0.1"])
        self.assertIn("localhost", info.sans)


# --------------------------------------------------------------- TLS probe


class TestTlsProbe(FixtureBase):
    def test_probe_valid_selfsigned(self):
        result = probe_tls(Target("127.0.0.1", self.port_tls), timeout=3)
        self.assertTrue(result.ok, result.error)
        self.assertIn("TLS", result.tls_version)
        self.assertTrue(result.cipher)
        self.assertEqual(result.cert.sans[0], "localhost")
        # No expiry warnings; the IP-SAN warning below is expected (the
        # fixture cert has DNS SANs only) and covered by its own test.
        self.assertFalse(
            any("expir" in w for w in result.warnings), result.warnings
        )
        # Self-signed must be reported as invalid, separately from extraction.
        self.assertTrue(result.validation.startswith("invalid"), result.validation)

    def test_probe_ip_target_without_ip_san_warns(self):
        # The fixture cert covers DNS names only — serving it on an IP
        # literal must be flagged, even though the chain is what fails
        # validation here (self-signed).
        result = probe_tls(Target("127.0.0.1", self.port_tls), timeout=3)
        self.assertTrue(result.ok, result.error)
        self.assertTrue(
            any("does not include IP 127.0.0.1" in w for w in result.warnings),
            result.warnings,
        )

    def test_probe_ip_target_with_ip_san_no_warning(self):
        result = probe_tls(Target("127.0.0.1", self.port_ip), timeout=3)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.cert.ip_sans, ["127.0.0.1"])
        self.assertFalse(
            any("does not include IP" in w for w in result.warnings),
            result.warnings,
        )

    def test_probe_expired(self):
        result = probe_tls(Target("127.0.0.1", self.port_expired), timeout=3)
        self.assertTrue(result.ok, result.error)
        self.assertLess(result.cert.days_left, 0)
        self.assertTrue(any("expired" in w for w in result.warnings))
        self.assertTrue(result.validation.startswith("invalid"), result.validation)

    def test_probe_connection_refused(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
        sock.close()
        result = probe_tls(Target("127.0.0.1", closed_port), timeout=2)
        self.assertFalse(result.ok)
        self.assertIn("refused", result.error)

    def test_probe_dns_failure(self):
        with mock.patch(
            "socket.create_connection",
            side_effect=socket.gaierror(-2, "Name or service not known"),
        ):
            result = probe_tls(Target("does-not-matter.test", 443), timeout=1)
        self.assertFalse(result.ok)
        self.assertIn("DNS", result.error)


# ------------------------------------------------------------- header grade


class TestGradeHeaders(unittest.TestCase):
    def test_full_set_scores_top(self):
        score, findings = grade_headers({k.lower(): v for k, v in FULL_HEADERS.items()})
        self.assertEqual(score, 100)
        self.assertEqual(findings, [])
        self.assertEqual(grade_for_score(score), "A+")

    def test_empty_set_scores_disclosure_only(self):
        score, findings = grade_headers({})
        self.assertEqual(score, 10)  # only the no-disclosure points
        self.assertEqual(grade_for_score(score), "F")
        self.assertTrue(any("Strict-Transport-Security" in f for f in findings))

    def test_weak_hsts_partial_credit(self):
        score, findings = grade_headers({"strict-transport-security": "max-age=1000"})
        self.assertEqual(score, 10 + 10)  # half HSTS + no-disclosure
        self.assertTrue(any("weak" in f for f in findings))

    def test_csp_unsafe_inline_not_strong(self):
        headers = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
        score, findings = grade_headers(headers)
        self.assertEqual(score, 12 + 10)  # half CSP + no-disclosure
        self.assertTrue(any("unsafe-inline" in f for f in findings))

    def test_csp_frame_ancestors_counts_as_framing(self):
        headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
        score, findings = grade_headers(headers)
        self.assertFalse(any("framing" in f for f in findings))
        self.assertEqual(score, 25 + 15 + 10)

    def test_version_disclosure_loses_points(self):
        score, findings = grade_headers({"server": "Apache/2.4.41"})
        self.assertEqual(score, 0)
        self.assertTrue(any("disclosure" in f for f in findings))

    def test_grade_boundaries(self):
        self.assertEqual(grade_for_score(95), "A+")
        self.assertEqual(grade_for_score(85), "A")
        self.assertEqual(grade_for_score(70), "B")
        self.assertEqual(grade_for_score(55), "C")
        self.assertEqual(grade_for_score(40), "D")
        self.assertEqual(grade_for_score(39), "F")


# ------------------------------------------------------------ header fetch


class TestFetchHeaders(FixtureBase):
    def test_fetch_over_tls(self):
        result = fetch_headers(Target("127.0.0.1", self.port_tls), scheme="https")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A+")

    def test_fetch_bare_server_low_grade(self):
        result = fetch_headers(Target("127.0.0.1", self.port_expired), scheme="https")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.grade, "F")

    def test_head_405_falls_back_to_get(self):
        result = fetch_headers(Target("127.0.0.1", self.port_http), scheme="http")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.score, 100)

    def test_http_falls_back_to_https(self):
        result = fetch_headers(Target("127.0.0.1", self.port_tls), scheme="http")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.scheme, "https")

    def test_redirect_relative_followed(self):
        result = fetch_headers(
            Target("127.0.0.1", self.port_redirect_rel), scheme="http"
        )
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.redirects, 1)
        self.assertTrue(result.final_url.endswith("/final"), result.final_url)

    def test_redirect_http_to_https_followed(self):
        result = fetch_headers(
            Target("127.0.0.1", self.port_redirect_to_tls), scheme="http"
        )
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.scheme, "https")
        self.assertEqual(result.score, 100)
        self.assertEqual(result.redirects, 1)

    def test_redirect_loop_detected(self):
        result = fetch_headers(
            Target("127.0.0.1", self.port_redirect_loop), scheme="http"
        )
        self.assertFalse(result.ok)
        self.assertIn("loop", result.error)

    def test_redirect_chain_too_many(self):
        result = fetch_headers(
            Target("127.0.0.1", self.port_redirect_chain), scheme="http"
        )
        self.assertFalse(result.ok)
        self.assertIn("too many redirects", result.error)

    def test_drip_feed_body_does_not_stall_fetch(self):
        # Regression (audit round 1): the GET fallback used to drain the
        # response body, so a slow-drip server stalled the scan forever.
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Drip(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                try:
                    for _ in range(1000):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.3)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Drip)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            started = time.time()
            # No do_HEAD -> 501 -> GET fallback against the drip feed.
            result = fetch_headers(
                Target("127.0.0.1", server.server_address[1]), timeout=3, scheme="http"
            )
            elapsed = time.time() - started
        finally:
            server.shutdown()
        self.assertTrue(result.ok, result.error)
        self.assertLess(elapsed, 5)


# ---------------------------------------------------------------- DNS check


class TestDnsCheck(unittest.TestCase):
    def test_resolves_true_and_false(self):
        with mock.patch(
            "llumen.dns_check.socket.getaddrinfo", return_value=[(socket.AF_INET,)]
        ):
            self.assertTrue(resolves("anything.test"))
        with mock.patch(
            "llumen.dns_check.socket.getaddrinfo",
            side_effect=socket.gaierror(-2, "NXDOMAIN"),
        ):
            self.assertFalse(resolves("gone.test"))

    def test_dangling_sans_skips_wildcard_and_self(self):
        with mock.patch(
            "llumen.dns_check.socket.getaddrinfo",
            side_effect=socket.gaierror(-2, "NXDOMAIN"),
        ):
            hints = dangling_sans(
                ["target.test", "*.wild.test", "dead.test"], exclude="target.test"
            )
        self.assertEqual(hints, ["dead.test"])

    def test_resolves_timeout_returns_none(self):
        # Regression: the stdlib resolver has no timeout, so a hung
        # resolver used to stall the worker (and the scan) forever.
        with mock.patch(
            "llumen.dns_check.socket.getaddrinfo",
            side_effect=lambda *a, **k: time.sleep(0.5),
        ):
            self.assertIsNone(resolves("slow.test", timeout=0.05))

    def test_check_sans_reports_timeouts_separately(self):
        def fake_getaddrinfo(host, *args, **kwargs):
            if host == "slow.test":
                time.sleep(0.5)
                return [(socket.AF_INET,)]
            raise socket.gaierror(-2, "NXDOMAIN")

        with mock.patch(
            "llumen.dns_check.socket.getaddrinfo", side_effect=fake_getaddrinfo
        ):
            result = check_sans(
                ["dead.test", "slow.test"], exclude="x.test", timeout=0.05
            )
        self.assertEqual(result.hints, ["dead.test"])
        self.assertEqual(result.timed_out, ["slow.test"])
        # The backwards-compatible wrapper drops timeouts — a slow
        # resolver must never manufacture a dangling hint.
        with mock.patch(
            "llumen.dns_check.socket.getaddrinfo", side_effect=fake_getaddrinfo
        ):
            self.assertEqual(
                dangling_sans(
                    ["dead.test", "slow.test"], exclude="x.test", timeout=0.05
                ),
                ["dead.test"],
            )


# --------------------------------------------------------------------- CLI


class TestCli(FixtureBase):
    def test_sanitize_strips_ansi_and_newlines(self):
        self.assertEqual(cli.sanitize("ok\x1b[31mred\nforged"), "ok[31mredforged")

    def test_end_to_end_json(self):
        out = self.tmp / "report.json"
        rc = cli.main(
            [
                f"127.0.0.1:{self.port_tls}",
                "--scheme",
                "https",
                "--no-dns-check",
                "--json",
                str(out),
            ]
        )
        self.assertEqual(rc, 0)
        records = json.loads(out.read_text())
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertTrue(rec["tls"]["ok"])
        self.assertEqual(rec["headers"]["grade"], "A+")
        self.assertIn("localhost", rec["tls"]["cert"]["sans"])
        self.assertIn("dns_timeouts", rec)
        self.assertEqual(rec["headers"]["redirects"], 0)

    def test_no_valid_targets_returns_2(self):
        self.assertEqual(cli.main(["bad host with spaces"]), 2)

    def test_bad_timeout_returns_2(self):
        self.assertEqual(cli.main(["example.com", "--timeout", "0"]), 2)

    def test_bad_port_returns_2(self):
        self.assertEqual(cli.main(["example.com", "--port", "70000"]), 2)
        self.assertEqual(cli.main(["example.com", "--port", "0"]), 2)


if __name__ == "__main__":
    unittest.main()
