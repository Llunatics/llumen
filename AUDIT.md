# Audit — llumen v1.1.1 (2026-11-24, Selasa)

First audit of the v1.1.0 upgrade (built 2026-11-23). Baseline suite
green first (44/44), then adversarial probes against the three new
features — redirect-following header grading, timeout-bound DNS, IP
SAN coverage — plus the report renderer. Two P1 crash bugs found, both
fixed in this round; the v1.1.0 features themselves held up.

## Findings

1. **[Fixed, P1] A hostile redirect crashed the whole scan.** Three
   shapes of `Location` header escaped `fetch_headers` as uncaught
   exceptions, propagated through `future.result()` in `main`, and
   killed the batch with a traceback (exit 1, no report, no JSON):
   `Location: http://127.0.0.1:99999/` → `ValueError: Port out of
   range 0-65535` (from `urlsplit().port`, outside the try block);
   `Location: http://[::1/` → `ValueError: Invalid IPv6 URL` (from
   `urljoin`/`hostname`); `Location: /café` → `UnicodeEncodeError`
   (non-ASCII request-target in `http.client`). Fix: the per-hop URL
   decomposition is wrapped in `try/except ValueError` (clean
   per-target error), the request `except` tuple gains `ValueError`,
   and `urljoin` is wrapped too. Regression tests for all three
   shapes, plus an end-to-end CLI test (rc 0, JSON written).
2. **[Fixed, P1] Rich markup injection crashed report rendering.**
   `render_rich` fed server-supplied strings to rich as markup:
   a header value of `[/link]` (via the `X-Frame-Options has unusual
   value: ...` finding) raised `rich.errors.MarkupError` in
   `console.print(details)` — CLI exit 1 *after* the table printed,
   and the JSON report was lost too (render precedes the JSON write).
   A `[bold]` value was silently consumed as a style instead. Fix:
   table cells are literal `rich.text.Text` and the details block is
   printed with `markup=False`. Regression tests: hostile-markup
   server end-to-end (rc 0) and a unit test pinning `[/link]`,
   `[bold]`, and `[SSL: WRONG_VERSION_NUMBER]` verbatim in output.
3. **[Fixed, P2] Redirect to port 0 silently graded port 80.**
   `port = parts.port or 80` treated the valid port `0` as missing,
   so `Location: http://127.0.0.1:0/` was graded from port 80 while
   `final_url` claimed `:0`. Fix: explicit `is not None` check; port
   0 is now fetched as port 0 (connection fails, clean error, nothing
   graded). Regression test with a live port-80 server proving no
   silent re-targeting.
4. **[Verified OK] IPv6 IP-SAN coverage.** Live `::1` TLS server with
   a minted cert carrying IP SAN `::1`: `ip_sans: ["::1"]`, no
   warning; DNS-only cert on the same target warns `certificate SAN
   does not include IP ::1`. The v4-mapped-v6 corner (`::ffff:127.0.0.1`
   SAN vs `127.0.0.1` target) warns — strict octet comparison per
   RFC 5280, left as-is.
5. **[Verified OK] DNS timeout behaviour.** Mocked 0.5 s resolver +
   0.05 s timeout returns `None`; `check_sans` splits dead vs slow
   names (suite). Negative timeout passed programmatically is
   harmless (`Thread.join` returns at once → `None`). No change.
6. **[Fixed, test harness] Unclosed fixture sockets.** `tearDownClass`
   only called `shutdown()`, leaving listening sockets bound — the
   port-80 fixture failed to rebind across test classes (test skipped
   in full runs) and the suite emitted 34 `ResourceWarning`s. Now
   `server_close()` is called too: 1 warning left (a single socket
   reaped at interpreter shutdown), no skips.

## Verification

- Suite **44 → 51 tests, all green** (local working tree), including
  the 7 new regression tests; re-run in a fresh clone of the pushed
  commit with a new venv + `pip install .`: 51/51 green.
- Adversarial probes re-run post-fix: bad-port / bad-IPv6 /
  non-ASCII redirect targets all return clean per-target errors;
  port-0 redirect returns a connection error with no grading;
  hostile-markup CLI exits 0 with `[/LINK]` printed literally.
- No regressions: all 44 pre-existing tests pass unchanged.

## Honest limitations (unchanged from v1.1.0)

- The dangling-SAN check still depends on the system resolver; a
  resolver that answers for every name will suppress hints. A timed-out
  lookup leaves a daemon worker thread behind until the resolver
  answers; threads are bounded by the 20-name cap per target.
- Header grading is presence + basic strength; it is a triage
  signal, not a security audit.
- No cipher-suite or protocol-downgrade testing (testssl.sh's job),
  no crawling, no active enumeration — by design.

## Verdict

v1.1.1 closes two crash-class holes a hostile server could use to
deny the whole batch report. The v1.1.0 features (timeout-bound DNS,
redirect-aware grading, IP SAN coverage) survived adversarial probing
intact. Solid as a fast, batch-safe TLS + header triage aid.

---

# Audit — llumen v1.1.0 (2026-11-23)

Upgrade build closing the three honest limitations admitted in the
v1.0.0 audit. Verified offline (44/44 tests) plus a fresh-install
re-run and a live local-server smoke test of the installed CLI.

## What changed

1. **[Fixed] Dangling-SAN check can no longer stall on a resolver.**
   `resolves()` ran the stdlib `getaddrinfo` with no timeout, so a
   pathological resolver could hang a worker thread indefinitely
   (bounded only by the 20-name cap). The lookup now runs in a daemon
   worker thread and is abandoned after `--dns-timeout` (default: the
   `--timeout` value). A timed-out lookup is reported separately
   (`dns_timeouts` in JSON, `? ... timed out` line in plain output) and
   is *never* flagged as dangling — a slow resolver cannot manufacture
   false takeover hints. Regression tests: a mocked 0.5 s resolver
   returns `None` after a 0.05 s timeout, and `check_sans` splits a
   dead name (hint) from a slow name (timed out).
2. **[Fixed] Header grading now follows redirects.** The fetch graded
   the first response, so a bare domain that 301s to its real site was
   graded on the redirect stub. `fetch_headers` now follows 301/302/
   303/307/308 (303 switches to GET) up to 5 hops — relative locations
   resolved via `urljoin`, cross-host and http<->https hops followed,
   non-HTTP(S) targets rejected — and grades the final response,
   recording hop count + final URL (`redirects`, `final_url`). Loops
   and chains over the cap are errors, not grades. Regression tests:
   relative 301 followed (score 100, 1 redirect), http→https 302
   followed, self-loop detected, 7-hop chain rejected as too many.
3. **[Fixed] IP-literal targets now get a SAN coverage check.**
   Validation used to verify the chain only, so a certificate issued
   for a DNS name served on a bare IP still read `valid`. Certificates
   are now parsed for IPAddress SANs (`ip_sans`, both `cryptography`
   and stdlib paths) and, for IP targets, the probe warns when the SAN
   does not include the target IP — and if the chain otherwise
   verifies, validation becomes `invalid: certificate SAN does not
   include IP <ip>` instead of a misleading `valid`. Regression tests:
   cert with an IP SAN for 127.0.0.1 parses and probes clean; the
   DNS-only fixture cert warns on the same IP.

## Verification

- Offline suite: **44/44 OK** (35 carried over + 9 new), run against
  the working tree and again against a fresh install (clean copy, new
  venv, `pip install .`, `llumen 1.1.0`).
- CLI smoke against local servers with the installed binary:
  http→https redirect graded A+ (100) after 1 hop; IP target without
  an IP SAN warned `certificate SAN does not include IP 127.0.0.1`;
  IP target with the IP SAN warned nothing and reported
  `ip_sans: ["127.0.0.1"]`; `--dns-timeout` accepted, `dns_timeouts`
  present in JSON.
- No regressions: all pre-existing tests pass unchanged except
  `test_probe_valid_selfsigned`, whose `assertFalse(warnings)` now
  asserts no *expiry* warnings — the IP-SAN warning is the intended
  new behaviour for that fixture cert and is covered by its own test.

## Honest limitations (updated)

- The dangling-SAN check still depends on the system resolver; a
  resolver that answers for every name (wildcard DNS, captive
  portals, intercepting proxies) will suppress hints. A timed-out
  lookup leaves a daemon worker thread behind until the resolver
  answers; threads are bounded by the 20-name cap per target.
- Header grading is presence + basic strength; it is a triage
  signal, not a security audit.
- No cipher-suite or protocol-downgrade testing (testssl.sh's job),
  no crawling, no active enumeration — by design.

## Verdict

v1.1.0 closes the three gaps the v1.0.0 audit admitted, with the same
offline-first verification discipline. The tool remains a fast,
batch-safe TLS + header triage aid — not a replacement for testssl.sh
or a full web security audit.

---

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
