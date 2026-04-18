"""Installed software, running-as-SYSTEM scheduled tasks, drivers, browsers."""

from .runner import Finding, Severity, Status, run_powershell, truncate


OUTDATED_PRODUCTS = [
    ("Adobe Flash", Severity.CRITICAL, "Flash Player has been EOL since 2021 and is never patched."),
    ("Java 6", Severity.HIGH, "Legacy Java with dozens of known RCEs."),
    ("Java 7", Severity.HIGH, "Unsupported since 2022."),
    ("Internet Explorer", Severity.HIGH, "IE is retired and still receives no patches for new bugs."),
    ("WinRAR 5.", Severity.HIGH, "Pre-6.23 WinRAR has CVE-2023-38831 exploited in the wild."),
    ("7-Zip 21.", Severity.HIGH, "Pre-22.x 7-Zip lacks several path-traversal fixes."),
    ("Notepad++ 7.", Severity.MEDIUM, "Older Notepad++ releases have known file-association RCEs."),
    ("TeamViewer 14", Severity.MEDIUM, "Very old TeamViewer versions have unpatched remote CVEs."),
    ("Zoom (5.0", Severity.MEDIUM, "Legacy Zoom installs are affected by multiple RCEs."),
]


def run():
    findings = []

    rc, out, _ = run_powershell(
        "$paths = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | "
        "Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 300"
    )
    installed = out or ""
    findings.append(Finding(
        name="Installed software inventory",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=truncate(installed, 8000),
    ))

    for needle, sev, desc in OUTDATED_PRODUCTS:
        if needle.lower() in installed.lower():
            hits = [l for l in installed.splitlines() if needle.lower() in l.lower()]
            findings.append(Finding(
                name=f"Outdated/risky product: {needle}",
                status=Status.FAIL,
                severity=sev,
                description=desc,
                evidence="\n".join(hits[:5]),
                recommendation="Uninstall or upgrade to a supported version.",
            ))

    rc, out, _ = run_powershell(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Where-Object { $_.State -ne 'Disabled' -and $_.Principal.UserId -in @('SYSTEM','NT AUTHORITY\\SYSTEM','S-1-5-18') -and $_.TaskPath -notlike '\\Microsoft\\*' } | "
        "Select-Object TaskPath,TaskName,@{n='Action';e={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '}} | "
        "Format-Table -AutoSize | Out-String -Width 300"
    )
    sys_tasks = (out or "").strip()
    if sys_tasks and len([l for l in sys_tasks.splitlines() if l.strip()]) > 2:
        findings.append(Finding(
            name="Non-Microsoft scheduled tasks running as SYSTEM",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="A scheduled task that runs as SYSTEM and points at a writable or non-default path is a classic persistence / privilege-escalation vector.",
            evidence=truncate(sys_tasks, 4000),
            recommendation="Audit each task. Verify the executable path is in a protected directory (Program Files, System32) and signed by a trusted publisher.",
        ))

    rc, out, _ = run_powershell(
        "Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | "
        "Where-Object { -not $_.IsSigned } | "
        "Select-Object DeviceName,DriverProviderName,DriverVersion,InfName | "
        "Format-Table -AutoSize | Out-String -Width 300"
    )
    unsigned = (out or "").strip()
    if unsigned and len([l for l in unsigned.splitlines() if l.strip()]) > 2:
        findings.append(Finding(
            name="Unsigned drivers detected",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Unsigned kernel-mode drivers bypass the normal trust chain — a frequent component of BYOVD attacks.",
            evidence=truncate(unsigned, 3000),
            recommendation="Replace unsigned drivers with vendor-signed versions, or remove the hardware.",
        ))

    rc, out, _ = run_powershell(
        "$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Office','HKCU:\\SOFTWARE\\Microsoft\\Office','HKCU:\\SOFTWARE\\Policies\\Microsoft\\Office'); "
        "Get-ChildItem -Path $paths -Recurse -ErrorAction SilentlyContinue | "
        "Where-Object { $_.PSChildName -eq 'Security' } | "
        "ForEach-Object { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue; "
        "if ($p.VBAWarnings -ne $null -or $p.BlockContentExecutionFromInternet -ne $null) { "
        "\"$($_.PSPath)  VBAWarnings=$($p.VBAWarnings)  BlockInternetMacros=$($p.BlockContentExecutionFromInternet)\" } }"
    )
    office = (out or "").strip()
    if office:
        bad = [l for l in office.splitlines() if "VBAWarnings=1" in l or ("BlockContentExecutionFromInternet=" in l and "BlockContentExecutionFromInternet=0" in l)]
        if bad:
            findings.append(Finding(
                name="Weak Office macro security policy",
                status=Status.WARN,
                severity=Severity.HIGH,
                description="VBAWarnings=1 is 'enable all macros without notification' — the most dangerous setting. Internet-sourced macros should always be blocked.",
                evidence=truncate("\n".join(bad), 2500),
                recommendation="Set VBAWarnings=4 (disable all) or 3 (disable with notification), and BlockContentExecutionFromInternet=1 for Word/Excel/PowerPoint/Outlook.",
            ))
        else:
            findings.append(Finding(
                name="Office macro policy (raw)",
                status=Status.INFO,
                severity=Severity.INFO,
                evidence=truncate(office, 2000),
            ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -ErrorAction SilentlyContinue; "
        "if ($p) { ($p | Format-List | Out-String) } else { 'ABSENT' }"
    )
    edge = (out or "").strip()
    if edge and edge != "ABSENT":
        findings.append(Finding(
            name="Edge policy configured",
            status=Status.INFO,
            severity=Severity.INFO,
            evidence=truncate(edge, 1500),
        ))

    rc, out, _ = run_powershell(
        "Get-Process -IncludeUserName -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Path -and ($_.Path -like '*\\Temp\\*' -or $_.Path -like '*\\Downloads\\*' -or $_.Path -like '*\\AppData\\Local\\Temp\\*') } | "
        "Select-Object ProcessName,Id,UserName,Path | Format-Table -AutoSize | Out-String -Width 300"
    )
    temp_proc = (out or "").strip()
    if temp_proc and len([l for l in temp_proc.splitlines() if l.strip()]) > 2:
        findings.append(Finding(
            name="Processes running from Temp / Downloads",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Binaries executing from user Temp or Downloads are a classic malware pattern.",
            evidence=truncate(temp_proc, 3000),
            recommendation="Investigate each process. Apply AppLocker / WDAC to block execution from user-writable paths.",
        ))

    rc, out, _ = run_powershell(
        "$env:Path -split ';' | ForEach-Object { $p = $_; if ($p -and (Test-Path $p)) { "
        "try { $acl = Get-Acl $p; foreach ($a in $acl.Access) { "
        "if ($a.IdentityReference -like '*Users*' -or $a.IdentityReference -like '*Everyone*' -or $a.IdentityReference -like '*Authenticated Users*') { "
        "if ($a.FileSystemRights -match 'Write|Modify|FullControl' -and $a.AccessControlType -eq 'Allow') { "
        "\"$p -- $($a.IdentityReference) $($a.FileSystemRights)\" } } } } catch { } } }"
    )
    path_issues = (out or "").strip()
    if path_issues:
        findings.append(Finding(
            name="Writable directories in PATH",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="A PATH directory writable by standard users lets an attacker drop binaries that admins will execute by accident — classic DLL/EXE search-order hijack.",
            evidence=truncate(path_issues, 3000),
            recommendation="Remove the directory from PATH or restrict its ACL to administrators and SYSTEM only.",
        ))

    rc, out, _ = run_powershell(
        "Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InstalledOn } | Measure-Object | Select-Object -ExpandProperty Count"
    )
    c = (out or "").strip()
    if c.isdigit():
        findings.append(Finding(
            name=f"Total hotfixes installed: {c}",
            status=Status.INFO,
            severity=Severity.INFO,
        ))

    return findings
