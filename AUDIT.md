# Audit — llumen v1.0.0 (2026-10-22)

Staged audit performed on the day of the build, in three rounds:
adversarial testing of v1, fixes, then a fresh-install re-audit.
The offline suite (35 tests) was green at the end of every round.

## Round 1 — adversarial inputs & hostile servers

Battery: IDN input (`bücher.de` → `xn--bcher-kva.de`), URLs with paths /
userinfo / uppercase / trailing dots, `host:port` forms, bracketed and
bare IPv6, an empty file, a comments-only file, a directory passed as
`--file`, a 300-entry list of dead domains, and two hostile local
servers (a `Server` header carrying an ANSI escape + forged log line,
and a slow-drip response body).

Findings:

1. **[Fixed] Unbounded response-body drain stalled scans forever.**
   The header fetcher drained the response body after a GET fallback.
   A server dripping one byte every 0.3 s kept `read()` alive
   indefinitely (each byte resets the socket inactivity timeout) —
   the audit script had to be killed after 30 s. Fix: the body is
   never read at all; only headers are graded, and the socket is
   closed immediately. Regression test added
   (`test_drip_feed_body_does_not_stall_fetch`); the same fetch now
   returns in < 0.1 s.
2. **[Verified OK] Terminal/log injection.** A `Server` header
   containing `ESC[31m` and an embedded newline was neutralized:
   all server-supplied strings pass through a control-character
   stripper before rendering or JSON output. Verified at the byte
   level — no control characters survive anywhere in a record.
3. **[Verified OK] Input handling.** Every malformed input was
   rejected with a clean reason and exit code 2 — no tracebacks.
   300 dead targets completed in ~1 s in this sandbox (fast-failing
   resolver), each recorded as a clean per-target error; on a real
   network the worst case per target is bounded by the worker pool
   and the per-stage `--timeout`.

## Round 2 — code review pass

Re-read of all four modules (`targets`, `tls_probe`, `header_check`,
`cli`, `dns_check`) for correctness and consistency defects:

1. **[Fixed] Ctrl-C waited for in-flight probes.** Exiting the
   thread-pool context manager blocked until every running probe hit
   its timeout (up to ~30 s with `--timeout 30`). Fix: on
   KeyboardInterrupt the pool cancels pending futures without
   waiting, partial results are rendered and written, and the
   process exits immediately with status 130. Verified against a
   stall server (accepts TCP, never speaks): SIGINT after 2 s →
   instant exit 130 with a valid (empty) partial JSON report.
2. **[Fixed] Asymmetric scheme fallback.** The http→https fallback
   retried HEAD only, while the primary path retried GET on
   405/501. The fallback now retries GET the same way.
3. **[Fixed] `--port` was not range-validated** when every target
   carried an explicit port (e.g. `--port 70000` was silently
   ignored). Now rejected with exit code 2; regression tests added.
4. **[Reviewed, no change]** No shell execution, `eval`, or
   string-formatted queries anywhere; every network operation is
   timeout-bound per stage (connect, handshake, validation, header
   fetch); JSON/file errors are handled; duplicate response headers
   are combined per RFC 9110 before grading.

## Round 3 — fresh-install re-audit

Clean copy of the tree (no virtualenv, no caches) into a scratch
directory, brand-new venv, regular `pip install .`:

- Test suite against the *installed* package: **35/35 OK**.
- CLI smoke: `llumen --version` → `llumen 1.0.0`; scan of a local
  plain-HTTP server correctly reports a TLS error for the probe and
  still fetches/grades headers (F, 0).
- Live test against real hosts (example.com, github.com,
  lab.llunaticsys.web.id): the full pipeline — probe, independent
  validation, grading, table + JSON — works end to end; header
  grades matched the origins' known postures (example.com F,
  github.com B/72, the Vercel-hosted blog F/20 with a weak-HSTS
  finding for a policy without `includeSubDomains`).

## Environment caveat (live test)

This build sandbox has no direct egress: DNS resolves public names
to sinkhole addresses and all traffic passes through a
TLS-intercepting egress proxy (certificates presented in-sandbox are
issued by the sandbox CA). The live test therefore ran the genuine
CLI through a CONNECT tunnel harness; header results are the real
origins', while in-sandbox certificate contents necessarily reflect
the interception CA. Certificate extraction correctness is proven by
the offline fixture suite (locally minted valid/expired/self-signed
certificates, no proxy involved). On a normal network llumen uses
plain direct sockets, as designed.

## Honest limitations

- The dangling-SAN check relies on the system resolver, which has no
  timeout control in Python's stdlib; a pathological resolver can
  stall a worker thread (bounded by the 20-name cap per target).
- Validation for IP-literal targets verifies the chain only, not
  hostname/SAN matching.
- Header grading is presence + basic strength; it is a triage
  signal, not a security audit, and redirects are not followed.
- No cipher-suite or protocol-downgrade testing (testssl.sh's job),
  no crawling, no active enumeration — by design.

## Verdict

Solid v1: a fast, batch-safe TLS + header triage tool whose failure
modes are all per-target, explicit, and bounded. It is a recon and
inventory aid — not a replacement for testssl.sh or a full web
security audit.
