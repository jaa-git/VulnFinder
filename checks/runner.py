import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"
    ERROR = "ERROR"


@dataclass
class Finding:
    name: str
    status: Status
    severity: Severity
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)


def run_command(args, timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError as e:
        return -2, "", f"not found: {e}"
    except Exception as e:
        return -3, "", f"{type(e).__name__}: {e}"


def run_powershell(script: str, timeout: int = 60) -> tuple[int, str, str]:
    return run_command(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ],
        timeout=timeout,
    )


def truncate(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"
