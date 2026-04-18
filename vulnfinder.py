import argparse
import ctypes
import os
import platform
import socket
import sys
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


def _colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    # Enable ANSI on recent Windows terminals
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return False
    return sys.stdout.isatty()


def print_console(results, host: str, colour: bool):
    def c(code, text):
        return f"{code}{text}{RESET}" if colour else text

    print()
    print(c("\033[1;97m", f"VulnFinder — {host}"))
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


def main():
    parser = argparse.ArgumentParser(description="VulnFinder — Windows 10/11 security audit")
    parser.add_argument("-o", "--output", default=None, help="Output PDF path (default: ./reports/vulnfinder_<host>_<timestamp>.pdf)")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation (console output only)")
    parser.add_argument("--quiet", action="store_true", help="Don't print per-finding lines to console")
    parser.add_argument("--offline", action="store_true", help="Skip the online vulnerability feed fetcher")
    args = parser.parse_args()

    if args.offline:
        os.environ["VULNFINDER_OFFLINE"] = "1"

    if os.name != "nt":
        print("VulnFinder targets Windows. Current platform:", platform.system())
        sys.exit(2)

    host = socket.gethostname()
    admin = is_admin()

    print(f"VulnFinder — scanning {host}")
    print(f"Admin:   {'yes' if admin else 'NO — many checks will be limited'}")
    print(f"OS:      {platform.platform()}")
    print(f"Python:  {platform.python_version()}")
    print()

    if not admin:
        print("[!] Running without administrator privileges.")
        print("    BitLocker, TPM, secedit, several registry reads and service queries will be")
        print("    incomplete. Re-run from an elevated terminal for a full audit.\n")

    print("Running checks...")
    results = []
    for category, module in checks.ALL_MODULES:
        print(f"  - {category}")
        try:
            if module is checks.feeds:
                findings = module.run(offline=args.offline)
            else:
                findings = module.run()
        except Exception as e:
            from checks.runner import Finding
            findings = [Finding(
                name=f"{category} check crashed",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                description=f"The {category} module raised {type(e).__name__}.",
                evidence=str(e),
            )]
        results.append((category, findings))

    print()
    if not args.quiet:
        print_console(results, host, colour=_colour_enabled())

    if not args.no_pdf:
        if args.output:
            out_path = Path(args.output)
        else:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = Path("reports") / f"vulnfinder_{host}_{stamp}.pdf"
        print(f"Writing PDF report to {out_path}...")
        build_report(results, host, out_path)
        print(f"Done: {out_path.resolve()}")

    # exit code: non-zero if any CRITICAL/HIGH fails
    critical = sum(1 for _, fs in results for f in fs if f.severity == Severity.CRITICAL and f.status in (Status.FAIL, Status.ERROR))
    high     = sum(1 for _, fs in results for f in fs if f.severity == Severity.HIGH and f.status in (Status.FAIL, Status.ERROR))
    if critical:
        sys.exit(2)
    if high:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
