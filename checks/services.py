from .runner import Finding, Severity, Status, run_powershell, truncate

RISKY_SERVICES = {
    "Telnet": ("Telnet server", Severity.CRITICAL, "Telnet transmits credentials and commands in clear text."),
    "TlntSvr": ("Telnet server", Severity.CRITICAL, "Telnet transmits credentials and commands in clear text."),
    "FTPSVC": ("IIS FTP server", Severity.HIGH, "FTP transmits credentials in clear text."),
    "SNMP": ("SNMP service", Severity.MEDIUM, "Legacy SNMPv1/v2c leak system info and use weak community strings."),
    "RemoteRegistry": ("Remote Registry", Severity.HIGH, "Remote Registry exposes the registry to the network — used for lateral movement and reconnaissance."),
    "SharedAccess": ("Internet Connection Sharing", Severity.MEDIUM, "ICS turns the host into a router/NAT — rarely wanted on a managed endpoint."),
    "WebClient": ("WebClient (WebDAV)", Severity.MEDIUM, "WebClient enables WebDAV, used in NTLM relay attacks."),
    "SSDPSRV": ("SSDP Discovery", Severity.LOW, "SSDP leaks device information on the local network."),
    "upnphost": ("UPnP Device Host", Severity.MEDIUM, "UPnP can auto-create inbound firewall holes."),
    "Fax": ("Fax service", Severity.LOW, "Rarely needed — reduce attack surface."),
    "SessionEnv": ("Remote Desktop Configuration", Severity.INFO, ""),
    "XblAuthManager": ("Xbox Live Auth", Severity.INFO, ""),
}


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-Service | Where-Object { $_.Status -eq 'Running' } | "
        "Select-Object Name,DisplayName,Status,StartType | "
        "Sort-Object Name | Format-Table -AutoSize | Out-String -Width 300"
    )
    findings.append(Finding(
        name="Running services",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=truncate(out or err, 6000),
    ))

    rc, map_out, _ = run_powershell(
        "Get-Service | Select-Object Name,Status,StartType | ForEach-Object { \"$($_.Name)|$($_.Status)|$($_.StartType)\" }"
    )
    running = {}
    for line in (map_out or "").splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            running[parts[0].strip()] = (parts[1].strip(), parts[2].strip())

    for name, (label, sev, desc) in RISKY_SERVICES.items():
        if name in running:
            status_val, start = running[name]
            if status_val == "Running":
                findings.append(Finding(
                    name=f"Risky service running: {name} ({label})",
                    status=Status.FAIL,
                    severity=sev,
                    description=desc,
                    evidence=f"{name}: Status={status_val} StartType={start}",
                    recommendation=f"Stop-Service {name}; Set-Service {name} -StartupType Disabled (if not required).",
                ))

    rc, exec_out, _ = run_powershell(
        "$policies = @{}; "
        "@('MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine') | ForEach-Object { "
        "$p = $_; $val = Get-ExecutionPolicy -Scope $p; \"$p=$val\" }"
    )
    exec_text = (exec_out or "").strip()
    findings.append(Finding(
        name="PowerShell execution policies",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=exec_text,
    ))
    if "LocalMachine=Unrestricted" in exec_text or "LocalMachine=Bypass" in exec_text:
        findings.append(Finding(
            name="PowerShell execution policy is Unrestricted/Bypass at machine scope",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Machine-wide Unrestricted or Bypass removes the lightweight ExecutionPolicy speed-bump against malicious scripts.",
            evidence=exec_text,
            recommendation="Set-ExecutionPolicy -Scope LocalMachine RemoteSigned (or AllSigned, with proper code-signing).",
        ))

    rc, script_out, _ = run_powershell(
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue | "
        "Select-Object EnableScriptBlockLogging | Format-List | Out-String"
    )
    sbl = (script_out or "").strip()
    if "EnableScriptBlockLogging : 1" not in sbl:
        findings.append(Finding(
            name="PowerShell script-block logging disabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Script-block logging records every PowerShell script executed — essential for detecting fileless/living-off-the-land attacks.",
            evidence=sbl or "Policy key absent",
            recommendation="Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging = 1 (DWORD).",
        ))

    rc, autorun_out, _ = run_powershell(
        "$keys = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; "
        "foreach ($k in $keys) { "
        "$p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue; "
        "if ($p) { \"--- $k ---\"; $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { \"  $($_.Name) = $($_.Value)\" } } "
        "}"
    )
    findings.append(Finding(
        name="Autorun entries (HKLM + HKCU Run/RunOnce)",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Autorun keys persist malware and should be reviewed against known-good baselines.",
        evidence=truncate(autorun_out or "", 4000),
    ))

    rc, insecure_out, _ = run_powershell(
        "Get-CimInstance Win32_Service | "
        "Where-Object { $_.PathName -and $_.PathName -notlike '\"*' -and $_.PathName -match '[A-Za-z]:\\\\.*\\s.*\\.exe' -and $_.PathName -notlike '%*' } | "
        "Select-Object Name,StartMode,StartName,PathName | Format-Table -AutoSize | Out-String -Width 300"
    )
    ins = (insecure_out or "").strip()
    ins_lines = [l for l in ins.splitlines() if l.strip() and not l.strip().startswith("----") and not l.strip().startswith("Name")]
    if ins_lines:
        findings.append(Finding(
            name="Services with unquoted paths containing spaces",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="An unquoted service path that contains spaces can be hijacked: if any parent directory is writable by a low-priv user, they can drop a binary that Windows will load as SYSTEM on next restart. Classic privilege escalation.",
            evidence=truncate(ins, 3000),
            recommendation="Quote the binary path: sc.exe config <svc> binPath= \"\\\"C:\\Program Files\\...\\app.exe\\\"\"  — and audit directory ACLs.",
        ))

    return findings
