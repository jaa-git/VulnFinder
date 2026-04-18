from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-HotFix | Sort-Object -Property InstalledOn -Descending | "
        "Select-Object -First 20 HotFixID,Description,InstalledOn | Format-Table -AutoSize | Out-String"
    )
    text = out or ""
    findings.append(Finding(
        name="Recently installed updates (top 20)",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=truncate(text or err),
    ))

    rc, age_out, _ = run_powershell(
        "$h = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1; "
        "if ($h) { ((Get-Date) - $h.InstalledOn).Days.ToString() } else { 'NONE' }"
    )
    days = (age_out or "").strip()
    if days.isdigit():
        d = int(days)
        if d > 90:
            findings.append(Finding(
                name=f"No updates installed in {d} days",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description="Missing patches leave known vulnerabilities exploitable. Patch Tuesday is monthly — 90+ days of lag is a sign the update mechanism is broken or disabled.",
                evidence=f"Most recent hotfix age: {d} days",
                recommendation="Run Windows Update, or check why it's failing (paused, metered connection, WSUS unreachable, wuauserv stopped).",
            ))
        elif d > 45:
            findings.append(Finding(
                name=f"No updates installed in {d} days",
                status=Status.WARN,
                severity=Severity.HIGH,
                evidence=f"Most recent hotfix age: {d} days",
                recommendation="Run Windows Update now.",
            ))
        else:
            findings.append(Finding(
                name=f"Most recent update: {d} days ago",
                status=Status.PASS,
                severity=Severity.INFO,
            ))
    elif days == "NONE":
        findings.append(Finding(
            name="No hotfixes recorded",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Get-HotFix returned no entries — very unusual on a patched Windows install.",
            recommendation="Investigate whether Windows Update is operational.",
        ))

    rc, svc_out, _ = run_powershell(
        "Get-Service -Name wuauserv,BITS,UsoSvc -ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,StartType | Format-Table | Out-String"
    )
    svc = svc_out or ""
    for svc_name in ("wuauserv", "BITS", "UsoSvc"):
        for line in svc.splitlines():
            if line.strip().startswith(svc_name):
                if "Disabled" in line:
                    findings.append(Finding(
                        name=f"{svc_name} service disabled",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        description=f"{svc_name} is required for Windows Update operations.",
                        evidence=line.strip(),
                        recommendation=f"Set-Service -Name {svc_name} -StartupType Manual (or Automatic for wuauserv).",
                    ))

    rc, au_out, _ = run_powershell(
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue | "
        "Select-Object NoAutoUpdate,AUOptions,UseWUServer | Format-List | Out-String"
    )
    au = au_out or ""
    if "NoAutoUpdate" in au:
        no_auto = [l for l in au.splitlines() if l.strip().startswith("NoAutoUpdate")]
        if no_auto and no_auto[0].strip().endswith(": 1"):
            findings.append(Finding(
                name="Automatic updates disabled via policy",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="A group policy has set NoAutoUpdate=1.",
                evidence=truncate(au),
                recommendation="Remove the NoAutoUpdate policy (or set to 0) unless updates are managed via WSUS/Intune with a working pipeline.",
            ))

    return findings
