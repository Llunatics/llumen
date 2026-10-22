# llumen

A fast TLS certificate and HTTP security header analyzer for the command line.

Give llumen a domain — or a file full of domains — and it reports, for each
target: the certificate (subject, issuer, SANs, expiry with days-left
warnings), the negotiated TLS version and cipher, an independent
certificate-validation verdict, a graded assessment of the HTTP security
headers, and passive hints about dangling SAN hostnames that may be exposed
to subdomain takeover.

Built for quick external attack-surface triage: recon before a pentest,
a sanity check on your own fleet, or feeding an EASM inventory.

## Features

- **Certificate extraction that never gives up early** — the probe uses an
  unverified handshake first, so self-signed and expired certificates still
  yield their data instead of aborting the scan. Validation is then checked
  with a separate, fully verified handshake and reported on its own line.
- **Expiry warnings** — expired, < 7 days, and < 30 days are flagged.
- **Header grading** — Strict-Transport-Security, Content-Security-Policy,
  X-Frame-Options / `frame-ancestors`, X-Content-Type-Options,
  Referrer-Policy, and Permissions-Policy are scored on a documented
  100-point rubric and graded A+ to F, with concrete findings.
- **Passive takeover hints** — SAN hostnames (other than the target itself
  and wildcards) that no longer resolve in DNS are flagged as possible
  dangling names. Passive only: no brute-forcing, no crawling, no active
  enumeration of any kind.
- **Batch-friendly** — one domain or thousands; bounded worker pool,
  per-connection timeouts (dead targets are skipped in seconds), terminal
  table via Rich plus a full JSON report for scripting. Ctrl-C prints the
  partial results collected so far and exits with status 130.
- **Adversarial-input safe** — IDN names are converted to Punycode, URLs
  and `host:port` forms are normalized, malformed lines are rejected with
  a reason (never a traceback), and all server-supplied strings are
  stripped of control characters before they reach your terminal or logs.

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Llunatics/llumen.git
cd llumen
python3 -m venv .venv
.venv/bin/pip install .
```

This installs the `llumen` command. Dependencies: `rich` (terminal table)
and `cryptography` (certificate parsing). If `rich` is unavailable, llumen
falls back to a plain-text report automatically.

## Usage

```bash
# Single target
llumen example.com

# Several targets, JSON report on the side
llumen example.com github.com --json report.json

# A file with one target per line (# comments allowed)
llumen --file domains.txt

# Non-standard port / scheme / timeout tuning
llumen internal.example.com:8443 --scheme https --timeout 5

# JSON straight to stdout (no table)
llumen example.com --json -
```

Accepted input forms: `example.com`, `example.com:8443`,
`https://example.com/some/path` (path ignored), IP literals, bracketed
IPv6 (`[::1]:8443`), and internationalized names (`bücher.de`).

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `-f, --file PATH` | — | Read targets from a file, one per line |
| `--port N` | 443 | Default port for bare hostnames |
| `--timeout SEC` | 3.0 | Per-connection timeout |
| `--scheme auto\|http\|https` | auto | Scheme for the header fetch (auto: https on port 443, else http, with cross-fallback) |
| `--workers N` | 8 | Parallel workers (max 16) |
| `--no-dns-check` | off | Skip the passive dangling-SAN check |
| `--json PATH` | — | Write the full report as JSON (`-` for stdout) |

Exit codes: `0` scan completed (per-target failures live in the report),
`1` the JSON report could not be written, `2` usage error / no valid
targets, `130` interrupted with Ctrl-C.

## Sample output

```
                          llumen — TLS & header report
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Target           ┃ Certificate       ┃ TLS     ┃ Validation ┃ Headers ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━┩
│ github.com:443   │ expires 2027-…    │ TLSv1.3 │ valid      │ B (72)  │
└──────────────────┴───────────────────┴─────────┴────────────┴─────────┘
== github.com:443 ==
  TLS cert : expires 2027-03-05 (…d left)
  TLS      : TLSv1.3 TLS_AES_256_GCM_SHA384
  Valid    : valid
  SANs     : github.com, www.github.com
  Headers  : grade B (72) [https 200]
  - CSP allows 'unsafe-inline'
  - missing Permissions-Policy
```

## How the header grade works

100 points total: HSTS 20 (full points need `max-age` ≥ 1 year and
`includeSubDomains`), CSP 25 (half for presence, the rest only if no
`'unsafe-inline'`, `'unsafe-eval'`, or wildcard sources), framing
protection 15, `X-Content-Type-Options: nosniff` 10, a strong
Referrer-Policy 10, Permissions-Policy 10, and no version disclosure in
`Server` / `X-Powered-By` 10. Grades: A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55,
D ≥ 40, F below that. The rubric is a triage signal, not an audit.

## Limitations

- **Deliberately out of scope:** cipher-suite enumeration and protocol
  downgrade testing (use testssl.sh), web crawling, active subdomain
  brute-forcing, and third-party takeover fingerprinting. The dangling-SAN
  check is a hint for manual verification, not a takeover verdict.
- Redirects are not followed for the header fetch; the first response is
  graded.
- For IP-literal targets, chain validation runs but hostname verification
  is skipped (there is no hostname), so `valid` means "chain verifies".
- The dangling-SAN check depends on the local resolver; a resolver that
  answers for every name (wildcard DNS, captive portals, intercepting
  proxies) will suppress hints.
- Header grading evaluates presence and basic strength only — it does not
  judge whether a CSP actually stops XSS in a given application.

## Development

The test suite is fully offline: it mints its own certificates
(valid self-signed and expired) and serves them from local TLS/HTTP
servers on 127.0.0.1.

```bash
python3 -m venv .venv
.venv/bin/pip install rich cryptography
PYTHONPATH=. .venv/bin/python -m unittest discover -s tests
```

See [AUDIT.md](AUDIT.md) for the staged audit history, findings, and
known limitations.

## License

MIT — see [LICENSE](LICENSE).
