"""Logging & visibility: event log sizing, PowerShell transcription, Sysmon."""

from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-WinEvent -ListLog 'Security','Application','System','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | "
        "Select-Object LogName,MaximumSizeInBytes,RecordCount,IsEnabled,LogFilePath | Format-Table -AutoSize | Out-String -Width 300"
    )
    text = out or ""
    findings.append(Finding(
        name="Event log configuration",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=truncate(text or err, 2000),
    ))

    rc, raw, _ = run_powershell(
        "Get-WinEvent -ListLog 'Security','Application','System' -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.LogName + '|' + $_.MaximumSizeInBytes }"
    )
    min_sizes = {
        "Security": 196608 * 1024,   # Microsoft baseline: 196,608 KB
        "Application": 32768 * 1024, # 32 MB
        "System": 32768 * 1024,
    }
    for line in (raw or "").splitlines():
        if "|" not in line:
            continue
        lname, sz = line.split("|", 1)
        try:
            sz_int = int(sz)
        except ValueError:
            continue
        minimum = min_sizes.get(lname.strip())
        if minimum and sz_int < minimum:
            findings.append(Finding(
                name=f"{lname.strip()} event log too small ({sz_int // 1024} KB)",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                description=f"An undersized event log wraps quickly and overwrites forensic evidence during an incident. Baseline minimum is {minimum // 1024} KB.",
                evidence=line,
                recommendation=f"wevtutil sl {lname.strip()} /ms:{minimum}",
            ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -ErrorAction SilentlyContinue; "
        "'EnableTranscripting=' + $p.EnableTranscripting + '|OutputDirectory=' + $p.OutputDirectory"
    )
    tr = (out or "").strip()
    if "EnableTranscripting=1" not in tr:
        findings.append(Finding(
            name="PowerShell transcription not enabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Transcription logs every PowerShell session to a file, surviving beyond script-block logging. Critical for incident response.",
            evidence=tr,
            recommendation="Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription\\EnableTranscripting=1 and OutputDirectory to a protected path.",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -ErrorAction SilentlyContinue; "
        "'EnableModuleLogging=' + $p.EnableModuleLogging"
    )
    ml = (out or "").strip()
    if "EnableModuleLogging=1" not in ml:
        findings.append(Finding(
            name="PowerShell module logging not enabled",
            status=Status.WARN,
            severity=Severity.LOW,
            description="Module logging records pipeline execution and parameter values for configured modules.",
            evidence=ml,
            recommendation="Enable via GPO: Computer > Admin Templates > Windows Components > Windows PowerShell > Turn on Module Logging (module names: *).",
        ))

    rc, out, _ = run_powershell(
        "(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table | Out-String)"
    )
    sm = (out or "").strip()
    if "Running" in sm:
        findings.append(Finding(
            name="Sysmon running",
            status=Status.PASS,
            severity=Severity.INFO,
            description="Sysmon is providing enriched process/network/file telemetry.",
            evidence=sm,
        ))
    else:
        findings.append(Finding(
            name="Sysmon not installed / not running",
            status=Status.WARN,
            severity=Severity.LOW,
            description="Sysmon provides process-lineage, hash and network telemetry that native logs don't capture. Recommended for monitored hosts.",
            evidence=sm or "Service not found.",
            recommendation="Install from https://learn.microsoft.com/sysinternals/downloads/sysmon with a curated config (SwiftOnSecurity / Olaf Hartong).",
        ))

    rc, out, _ = run_powershell(
        "(Get-Service -Name 'MpsSvc','EventLog','WinDefend' -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table | Out-String)"
    )
    core = (out or "").strip()
    if "Stopped" in core:
        findings.append(Finding(
            name="Core logging/defence service stopped",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="EventLog, MpsSvc (Firewall) and WinDefend must all be running.",
            evidence=core,
            recommendation="Start the stopped service and investigate why it was stopped — attackers commonly stop these.",
        ))

    return findings
