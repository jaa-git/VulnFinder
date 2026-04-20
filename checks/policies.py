from .runner import Finding, Severity, Status, run_command, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_command(["net.exe", "accounts"])
    net_out = out or ""
    findings.append(Finding(
        name="Local password & lockout policy",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Output of `net accounts` — baseline local policy.",
        evidence=truncate(net_out or err),
    ))

    policy = _parse_net_accounts(net_out)

    min_len = policy.get("min_length")
    if min_len is not None:
        if min_len < 8:
            findings.append(Finding(
                name=f"Minimum password length is {min_len}",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="Minimum length under 8 makes offline cracking feasible in minutes on commodity GPUs.",
                evidence=f"Minimum password length = {min_len}",
                recommendation="net accounts /minpwlen:14 (or enforce via AD/Intune).",
            ))
        elif min_len < 12:
            findings.append(Finding(
                name=f"Minimum password length is {min_len}",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                evidence=f"Minimum password length = {min_len}",
                recommendation="Raise to 14 aligned with Microsoft Security Baseline.",
            ))
        else:
            findings.append(Finding(
                name=f"Minimum password length: {min_len}",
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=f"Minimum password length = {min_len}",
            ))

    max_age = policy.get("max_age")
    if max_age == 0 or max_age is None:
        pass  # acceptable under newer guidance
    elif max_age > 365:
        findings.append(Finding(
            name=f"Password expiry > 1 year ({max_age} days)",
            status=Status.WARN,
            severity=Severity.LOW,
            evidence=f"Maximum password age = {max_age}",
        ))

    lockout = policy.get("lockout_threshold")
    if lockout == 0:
        findings.append(Finding(
            name="Account lockout threshold is 0 (never lock)",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="With no lockout, online brute-force and password spraying against this host have effectively unlimited attempts.",
            evidence="Lockout threshold = 0",
            recommendation="net accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15",
        ))
    elif lockout and lockout > 20:
        findings.append(Finding(
            name=f"Account lockout threshold very high ({lockout})",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            evidence=f"Lockout threshold = {lockout}",
            recommendation="Set to 10 or fewer attempts.",
        ))

    history = policy.get("history")
    if history is not None and history < 5:
        findings.append(Finding(
            name=f"Password history remembers only {history} passwords",
            status=Status.WARN,
            severity=Severity.LOW,
            evidence=f"history = {history}",
            recommendation="net accounts /uniquepw:24",
        ))

    rc, sp_out, sp_err = run_powershell(
        "$tmp = [System.IO.Path]::GetTempFileName(); "
        "secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null; "
        "Get-Content $tmp; Remove-Item $tmp -Force"
    )
    seced = sp_out or ""
    if seced.strip():
        relevant = []
        for line in seced.splitlines():
            for key in (
                "PasswordComplexity",
                "MinimumPasswordAge",
                "ClearTextPassword",
                "LockoutDuration",
                "ResetLockoutCount",
                "AuditAccountLogon",
                "AuditLogonEvents",
                "AuditPolicyChange",
                "AuditPrivilegeUse",
                "AuditObjectAccess",
                "AuditProcessTracking",
                "AuditSystemEvents",
            ):
                if line.strip().startswith(key):
                    relevant.append(line.strip())

        if relevant:
            findings.append(Finding(
                name="Local security policy (secedit extract)",
                status=Status.INFO,
                severity=Severity.INFO,
                evidence="\n".join(relevant),
            ))

        for line in relevant:
            if line.startswith("PasswordComplexity") and line.endswith("= 0"):
                findings.append(Finding(
                    name="Password complexity disabled",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description="Complexity off allows all-lowercase or simple passwords.",
                    evidence=line,
                    recommendation="Enable complexity via secedit / Local Security Policy / GPO.",
                ))
            if line.startswith("ClearTextPassword") and line.endswith("= 1"):
                findings.append(Finding(
                    name="Store passwords using reversible encryption",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    description="Reversible encryption stores passwords recoverable in plain text.",
                    evidence=line,
                    recommendation="Set ClearTextPassword = 0.",
                ))

    rc, audit_out, _ = run_command(["auditpol.exe", "/get", "/category:*"])
    audit = audit_out or ""
    if audit:
        no_audit = []
        for line in audit.splitlines():
            parts = line.rsplit("  ", 1)
            if len(parts) == 2:
                name_part = parts[0].strip()
                action = parts[1].strip()
                if name_part and action == "No Auditing" and name_part not in (
                    "System audit policy", "Category/Subcategory", "Setting"
                ):
                    no_audit.append(line.strip())
        if no_audit:
            findings.append(Finding(
                name=f"{len(no_audit)} audit subcategories set to 'No Auditing'",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                description="Without auditing, forensic reconstruction of an incident is severely limited. At minimum, Logon, Account Management, Privilege Use and Process Creation should be audited for Success/Failure.",
                evidence="\n".join(no_audit[:30]) + ("\n..." if len(no_audit) > 30 else ""),
                recommendation="Apply the Microsoft Security Baseline audit policy, or at least auditpol /set /subcategory:'Logon' /success:enable /failure:enable for the critical categories.",
            ))
        else:
            findings.append(Finding(
                name="All audit subcategories have some auditing configured",
                status=Status.PASS,
                severity=Severity.INFO,
            ))

    return findings


def _parse_net_accounts(text: str) -> dict:
    out = {}
    keys = (
        ("minimum password length", "min_length"),
        ("maximum password age", "max_age"),
        ("minimum password age", "min_age"),
        ("length of password history", "history"),
        ("lockout threshold", "lockout_threshold"),
        ("lockout duration", "lockout_duration"),
        ("lockout observation window", "lockout_window"),
    )
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.rsplit(None, 1)
        if not parts:
            continue
        val = parts[-1].strip()
        if not val:
            continue
        lower = line.lower()
        for needle, key in keys:
            if needle in lower:
                out[key] = _to_int(val)
                break
    return out


def _to_int(v: str):
    try:
        return int(v)
    except ValueError:
        if v.lower() == "never":
            return 0
        return None
