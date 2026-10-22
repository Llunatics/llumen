"""llumen command-line interface.

Usage:
    llumen example.com
    llumen example.com github.com --json report.json
    llumen --file domains.txt --timeout 3
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

from . import __version__
from .dns_check import dangling_sans
from .header_check import fetch_headers
from .targets import Target, load_targets, parse_target, TargetError
from .tls_probe import probe_tls

MAX_WORKERS = 16
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize(text: str) -> str:
    """Strip control characters (incl. ANSI escapes) from server-supplied
    strings before they reach the terminal or logs (log-forging defense)."""
    return _CTRL_RE.sub("", text)


def _sanitize_obj(obj):
    if isinstance(obj, str):
        return sanitize(obj)
    if isinstance(obj, list):
        return [_sanitize_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _sanitize_obj(v) for k, v in obj.items()}
    return obj


def scan_target(target: Target, timeout: float, check_dns: bool, scheme: str) -> dict:
    tls = probe_tls(target, timeout=timeout)
    headers = fetch_headers(target, timeout=timeout, scheme=scheme)
    record = {
        "target": str(target),
        "host": target.host,
        "port": target.port,
        "tls": asdict(tls),
        "headers": asdict(headers),
        "takeover_hints": [],
    }
    if check_dns and tls.cert and tls.cert.sans:
        record["takeover_hints"] = dangling_sans(tls.cert.sans, exclude=target.host)
    return _sanitize_obj(record)


def _grade_cell(record: dict) -> str:
    headers = record["headers"]
    if headers.get("ok"):
        return f"{headers['grade']} ({headers['score']})"
    return "-"


def _cert_cell(record: dict) -> str:
    tls = record["tls"]
    cert = tls.get("cert")
    if not tls.get("ok") or not cert:
        return tls.get("error") or "no certificate"
    days = cert.get("days_left")
    days_txt = f"{days}d left" if days is not None else "?"
    return f"expires {cert.get('not_after', '')[:10]} ({days_txt})"


def render_plain(records: list[dict]) -> str:
    lines = []
    for rec in records:
        lines.append(f"== {rec['target']} ==")
        lines.append(f"  TLS cert : {_cert_cell(rec)}")
        tls = rec["tls"]
        if tls.get("ok"):
            lines.append(f"  TLS      : {tls.get('tls_version')} {tls.get('cipher')}".rstrip())
            lines.append(f"  Valid    : {tls.get('validation')}")
            cert = tls.get("cert") or {}
            sans = cert.get("sans") or []
            if sans:
                lines.append(f"  SANs     : {', '.join(sans)}")
            for warning in tls.get("warnings", []):
                lines.append(f"  ! {warning}")
        headers = rec["headers"]
        if headers.get("ok"):
            lines.append(
                f"  Headers  : grade {_grade_cell(rec)} "
                f"[{headers.get('scheme')} {headers.get('status')}]"
            )
            for finding in headers.get("findings", []):
                lines.append(f"  - {finding}")
        elif headers.get("error"):
            lines.append(f"  Headers  : {headers['error']}")
        for hint in rec.get("takeover_hints", []):
            lines.append(f"  ? SAN {hint} does not resolve (possible dangling name)")
        lines.append("")
    return "\n".join(lines)


def render_rich(records: list[dict]) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="llumen — TLS & header report", show_lines=False)
    table.add_column("Target", style="bold")
    table.add_column("Certificate")
    table.add_column("TLS")
    table.add_column("Validation")
    table.add_column("Headers")
    for rec in records:
        tls = rec["tls"]
        tls_txt = (
            f"{tls.get('tls_version', '')} {tls.get('cipher', '')}".strip()
            if tls.get("ok")
            else "-"
        )
        table.add_row(
            rec["target"],
            _cert_cell(rec),
            tls_txt or "-",
            tls.get("validation", "-") if tls.get("ok") else "-",
            _grade_cell(rec),
        )
    console.print(table)
    details = render_plain(
        [
            rec
            for rec in records
            if rec["tls"].get("warnings")
            or rec["headers"].get("findings")
            or rec.get("takeover_hints")
            or not rec["tls"].get("ok")
        ]
    )
    if details.strip():
        console.print(details)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llumen",
        description="Fast TLS certificate and HTTP security header analyzer.",
    )
    parser.add_argument("targets", nargs="*", help="domains, host:port, or URLs")
    parser.add_argument("-f", "--file", help="file with one target per line")
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="default port for bare hostnames (default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="per-connection timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--scheme",
        choices=("auto", "http", "https"),
        default="auto",
        help="scheme for the header fetch (default: auto)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="parallel workers (default: 8, max 16)",
    )
    parser.add_argument(
        "--no-dns-check",
        action="store_true",
        help="skip the passive dangling-SAN (takeover hint) check",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="also write the full report as JSON to PATH ('-' for stdout)",
    )
    parser.add_argument("--version", action="version", version=f"llumen {__version__}")
    return parser


def collect_targets(args) -> tuple[list[Target], list[str]]:
    """Return (targets, error_messages)."""
    errors: list[str] = []
    all_targets: list[Target] = []
    seen: set[Target] = set()

    def add(target: Target) -> None:
        if target not in seen:
            seen.add(target)
            all_targets.append(target)

    for raw in args.targets:
        try:
            add(parse_target(raw, default_port=args.port))
        except TargetError as exc:
            errors.append(f"invalid target {raw!r}: {exc}")

    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                file_targets, file_errors = load_targets(fh, default_port=args.port)
        except OSError as exc:
            errors.append(f"cannot read file {args.file!r}: {exc}")
        else:
            for target in file_targets:
                add(target)
            for lineno, raw, reason in file_errors:
                errors.append(f"{args.file}:{lineno}: rejected {raw!r}: {reason}")
    return all_targets, errors


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return 2
    if not (1 <= args.port <= 65535):
        print("error: --port must be between 1 and 65535", file=sys.stderr)
        return 2
    targets, errors = collect_targets(args)
    for message in errors:
        print(f"warning: {message}", file=sys.stderr)
    if not targets:
        print("error: no valid targets", file=sys.stderr)
        return 2

    workers = max(1, min(args.workers, MAX_WORKERS))
    records: list[dict] = []
    interrupted = False
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {
            pool.submit(
                scan_target, target, args.timeout, not args.no_dns_check, args.scheme
            ): target
            for target in targets
        }
        for future in as_completed(futures):
            records.append(future.result())
    except KeyboardInterrupt:
        interrupted = True
        print("\ninterrupted — showing partial results", file=sys.stderr)
    finally:
        # On interrupt, do not wait for in-flight probes: cancel what has
        # not started and let the exit path below force-quit the process
        # so Ctrl-C feels instant even mid-scan.
        pool.shutdown(wait=not interrupted, cancel_futures=interrupted)

    order = {str(t): i for i, t in enumerate(targets)}
    records.sort(key=lambda r: order.get(r["target"], 0))

    if records:
        if args.json == "-":
            print(json.dumps(records, indent=2))
        else:
            try:
                import rich  # noqa: F401

                render_rich(records)
            except ImportError:
                print(render_plain(records))

    if args.json and args.json != "-":
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(records, fh, indent=2)
        except OSError as exc:
            print(f"error: cannot write JSON report: {exc}", file=sys.stderr)
            return 1

    if interrupted:
        sys.stdout.flush()
        sys.stderr.flush()
        # Worker threads are non-daemon; a normal return would block on
        # them until every in-flight probe times out. Results are already
        # printed and written, so exit immediately with the conventional
        # SIGINT status.
        os._exit(130)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
