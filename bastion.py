import argparse
import ctypes
import json
import os
import platform
import re
import socket
import sys
import traceback
from datetime import datetime
from pathlib import Path

import checks
from checks.runner import Severity, Status
from report import build_report


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


SEV_COLOUR_ANSI = {
    Severity.CRITICAL: "\033[41;97m",
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[34m",
    Severity.INFO:     "\033[90m",
}
STATUS_COLOUR_ANSI = {
    Status.PASS:  "\033[32m",
    Status.FAIL:  "\033[31m",
    Status.WARN:  "\033[33m",
    Status.INFO:  "\033[90m",
    Status.ERROR: "\033[35m",
}
RESET = "\033[0m"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


class _Tee:
    """Duplicate writes to stdout/stderr and a log file on disk.

    The console stream keeps ANSI colour; the on-disk copy is stripped so
    the log stays readable in Notepad.
    """

    def __init__(self, console, log_file):
        self.console = console
        self.log_file = log_file

    def write(self, data):
        if not isinstance(data, str):
            try:
                data = data.decode("utf-8", errors="replace")
            except Exception:
                data = str(data)
        try:
            self.console.write(data)
        except Exception:
            pass
        try:
            self.log_file.write(_ANSI_RE.sub("", data))
            self.log_file.flush()
        except Exception:
            pass
        return len(data)

    def flush(self):
        for s in (self.console, self.log_file):
            try:
                s.flush()
            except Exception:
                pass

    def isatty(self):
        try:
            return bool(self.console.isatty())
        except Exception:
            return False


def print_console(results, host: str, colour: bool):
    def c(code, text):
        return f"{code}{text}{RESET}" if colour else text

    print()
    print(c("\033[1;97m", f"Bastion — {host}"))
    print(c("\033[90m", f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print()

    sev_counts = {s: 0 for s in Severity}
    stat_counts = {s: 0 for s in Status}
    for _, findings in results:
        for f in findings:
            sev_counts[f.severity] += 1
            stat_counts[f.status] += 1

    print(c("\033[1m", "Summary"))
    print(
        "  " +
        c(SEV_COLOUR_ANSI[Severity.CRITICAL], f"CRITICAL: {sev_counts[Severity.CRITICAL]}") + "   " +
        c(SEV_COLOUR_ANSI[Severity.HIGH],     f"HIGH: {sev_counts[Severity.HIGH]}") + "   " +
        c(SEV_COLOUR_ANSI[Severity.MEDIUM],   f"MEDIUM: {sev_counts[Severity.MEDIUM]}") + "   " +
        c(SEV_COLOUR_ANSI[Severity.LOW],      f"LOW: {sev_counts[Severity.LOW]}") + "   " +
        c(SEV_COLOUR_ANSI[Severity.INFO],     f"INFO: {sev_counts[Severity.INFO]}")
    )
    print(
        "  " +
        c(STATUS_COLOUR_ANSI[Status.PASS],  f"PASS: {stat_counts[Status.PASS]}") + "   " +
        c(STATUS_COLOUR_ANSI[Status.FAIL],  f"FAIL: {stat_counts[Status.FAIL]}") + "   " +
        c(STATUS_COLOUR_ANSI[Status.WARN],  f"WARN: {stat_counts[Status.WARN]}") + "   " +
        c(STATUS_COLOUR_ANSI[Status.ERROR], f"ERROR: {stat_counts[Status.ERROR]}")
    )
    print()

    for category, findings in results:
        print(c("\033[1;96m", f"[ {category} ]"))
        for f in findings:
            tag = c(SEV_COLOUR_ANSI[f.severity], f"{f.severity.value:<8}") + " " + c(STATUS_COLOUR_ANSI[f.status], f"{f.status.value:<5}")
            print(f"  {tag}  {f.name}")
        print()


def findings_to_dict(results, host: str, admin: bool) -> dict:
    cats = []
    totals_sev = {s.value: 0 for s in Severity}
    totals_stat = {s.value: 0 for s in Status}
    for cat, findings in results:
        items = []
        for f in findings:
            totals_sev[f.severity.value] += 1
            totals_stat[f.status.value] += 1
            items.append({
                "name": f.name,
                "status": f.status.value,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "references": list(f.references or []),
            })
        cats.append({"category": cat, "findings": items})
    return {
        "host": host,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "admin": admin,
        "os": platform.platform(),
        "python": platform.python_version(),
        "totals": {"by_severity": totals_sev, "by_status": totals_stat},
        "categories": cats,
    }


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def _resolve_run_dir(custom: str | None, host: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if custom:
        base = Path(custom).expanduser()
        if not base.is_absolute():
            base = _base_dir() / base
    else:
        base = _base_dir() / "reports" / f"bastion_{host}_{stamp}"

    # Try to create it. If permission denied, fall back to the user profile.
    for candidate in (base, Path.home() / "Documents" / "Bastion" / f"bastion_{host}_{stamp}"):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # sanity write test
            test = candidate / ".write_test"
            test.write_text("ok", encoding="utf-8")
            test.unlink()
            return candidate
        except Exception:
            continue
    # last resort: tempdir
    import tempfile
    fallback = Path(tempfile.gettempdir()) / f"bastion_{host}_{stamp}"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _pause_if_frozen():
    """Keep the console open when running as a frozen exe.

    Unconditional when frozen — safer than trying to detect whether the user
    launched us from an existing shell. Accepts Enter or a timeout.
    """
    if not getattr(sys, "frozen", False):
        return
    print()
    print("Press Enter to close this window.")
    try:
        input()
    except EOFError:
        pass
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Bastion — Windows 10/11 security audit")
    parser.add_argument("-o", "--output", default=None,
                        help="Output folder (default: <exe-dir>\\reports\\bastion_<host>_<timestamp>\\). "
                             "The PDF, scan log and findings.json will all be written inside.")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation (log + JSON only)")
    parser.add_argument("--quiet", action="store_true", help="Don't print per-finding lines")
    parser.add_argument("--offline", action="store_true", help="Skip the online vulnerability feed fetcher")
    parser.add_argument("--no-pause", action="store_true", help="Don't pause at end when frozen")
    args = parser.parse_args()

    if args.offline:
        os.environ["BASTION_OFFLINE"] = "1"

    if os.name != "nt":
        print("Bastion targets Windows. Current platform:", platform.system())
        sys.exit(2)

    host = socket.gethostname()
    admin = is_admin()

    run_dir = _resolve_run_dir(args.output, host)
    log_path = run_dir / "scan.log"
    pdf_path = run_dir / "report.pdf"
    json_path = run_dir / "findings.json"
    error_path = run_dir / "error.log"

    log_file = open(log_path, "w", encoding="utf-8", errors="replace")
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = _Tee(original_stdout, log_file)
    sys.stderr = _Tee(original_stderr, log_file)

    exit_code = 0
    try:
        print(f"Bastion — scanning {host}")
        print(f"Output:  {run_dir}")
        print(f"Admin:   {'yes' if admin else 'NO — many checks will be limited'}")
        print(f"OS:      {platform.platform()}")
        print(f"Python:  {platform.python_version()}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        if not admin:
            print("[!] Running without administrator privileges.")
            print("    BitLocker, TPM, secedit, several registry reads and service queries will be")
            print("    incomplete. Re-run from an elevated terminal for a full audit.\n")

        print("Running checks...")
        results = []
        for category, module in checks.ALL_MODULES:
            t0 = datetime.now()
            print(f"  - {category} ... ", end="", flush=True)
            try:
                if module is checks.feeds:
                    findings = module.run(offline=args.offline)
                else:
                    findings = module.run()
                dt = (datetime.now() - t0).total_seconds()
                print(f"{len(findings)} findings [{dt:.1f}s]")
            except Exception as e:
                from checks.runner import Finding
                dt = (datetime.now() - t0).total_seconds()
                print(f"CRASH [{dt:.1f}s]  {type(e).__name__}: {e}")
                traceback.print_exc()
                findings = [Finding(
                    name=f"{category} check crashed",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    description=f"The {category} module raised {type(e).__name__}.",
                    evidence=f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
                )]
            results.append((category, findings))

        print()
        if not args.quiet:
            print_console(results, host, colour=_colour_enabled())

        # Always write findings.json
        try:
            json_path.write_text(
                json.dumps(findings_to_dict(results, host, admin), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"Findings JSON: {json_path}")
        except Exception as e:
            print(f"[!] Could not write findings.json: {type(e).__name__}: {e}")

        # PDF
        if not args.no_pdf:
            print(f"Writing PDF report to {pdf_path}...")
            try:
                build_report(results, host, pdf_path)
                print(f"Done: {pdf_path}")
            except Exception as e:
                err_msg = f"PDF generation failed: {type(e).__name__}: {e}\n{traceback.format_exc()}"
                print(f"[!!] {err_msg}")
                try:
                    error_path.write_text(err_msg, encoding="utf-8")
                except Exception:
                    pass
                exit_code = 3

        critical = sum(1 for _, fs in results for f in fs if f.severity == Severity.CRITICAL and f.status in (Status.FAIL, Status.ERROR))
        high = sum(1 for _, fs in results for f in fs if f.severity == Severity.HIGH and f.status in (Status.FAIL, Status.ERROR))
        print(f"\nFinished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Run folder: {run_dir}")

        if exit_code == 0:
            if critical:
                exit_code = 2
            elif high:
                exit_code = 1

    except SystemExit:
        raise
    except Exception as e:
        err_msg = f"Unhandled error: {type(e).__name__}: {e}\n{traceback.format_exc()}"
        print(f"\n[!!] {err_msg}")
        try:
            error_path.write_text(err_msg, encoding="utf-8")
        except Exception:
            pass
        exit_code = 4
    finally:
        # Restore streams and flush log before exiting.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        try:
            log_file.close()
        except Exception:
            pass

    if not args.no_pause:
        _pause_if_frozen()

    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        # Shouldn't happen — main() has its own handler — but belt & braces.
        print()
        print(f"[!!] Fatal: {type(e).__name__}: {e}")
        traceback.print_exc()
        _pause_if_frozen()
        sys.exit(5)
