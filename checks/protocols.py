"""Name-resolution poisoning surface and legacy protocol exposure: LLMNR, NetBIOS, WPAD, mDNS, PowerShell v2, Print Spooler, WSH."""

from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -ErrorAction SilentlyContinue; "
        "'EnableMulticast=' + $p.EnableMulticast"
    )
    llmnr = (out or "").strip()
    if "EnableMulticast=0" not in llmnr:
        findings.append(Finding(
            name="LLMNR enabled (multicast name resolution)",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="LLMNR falls back to broadcast name lookups that any attacker on the same LAN segment can answer — standard Responder.py attack capturing NTLMv2 hashes.",
            evidence=llmnr,
            recommendation="Create HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast (DWORD) = 0 (or disable via GPO Computer > Admin Templates > Network > DNS Client > Turn off multicast name resolution).",
        ))
    else:
        findings.append(Finding(
            name="LLMNR disabled",
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=llmnr,
        ))

    rc, out, _ = run_powershell(
        "Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
        "Select-Object Description,TcpipNetbiosOptions | Format-Table -AutoSize | Out-String"
    )
    nb = out or ""
    if nb.strip():
        bad = []
        for line in nb.splitlines():
            parts = line.rsplit(None, 1)
            if len(parts) == 2 and parts[1].strip().isdigit():
                if int(parts[1].strip()) != 2:  # 0=default, 1=enable, 2=disable
                    bad.append(line.strip())
        if bad:
            findings.append(Finding(
                name="NetBIOS-over-TCP not disabled on all adapters",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="NetBIOS broadcast name resolution is as abusable as LLMNR. Should be explicitly disabled (option 2).",
                evidence=truncate(nb),
                recommendation="On each adapter set TcpipNetbiosOptions = 2: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_*' -Name NetbiosOptions -Value 2",
            ))
        else:
            findings.append(Finding(
                name="NetBIOS-over-TCP disabled on all adapters",
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=truncate(nb),
            ))

    rc, out, _ = run_powershell(
        "(Get-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue).Status; "
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue | Select-Object AutoDetect | Format-List | Out-String"
    )
    wpad = (out or "").strip()
    if "AutoDetect : 1" in wpad or "AutoDetect : True" in wpad:
        findings.append(Finding(
            name="WPAD auto-detect enabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Web Proxy Auto-Discovery broadcasts for wpad.dat — an attacker can answer with a malicious proxy. Classic MitM.",
            evidence=truncate(wpad),
            recommendation="Disable 'Automatically detect settings' in Internet Options, or push the registry setting via GPO.",
        ))

    rc, out, _ = run_powershell(
        "(Get-Service -Name 'Bonjour Service','mDNSResponder' -ErrorAction SilentlyContinue) | "
        "Select-Object Name,Status | Format-Table | Out-String"
    )
    mdns = (out or "").strip()
    if "Running" in mdns:
        findings.append(Finding(
            name="mDNS (Bonjour) service running",
            status=Status.WARN,
            severity=Severity.LOW,
            description="mDNS adds another broadcast name-resolution channel. Rarely needed on enterprise endpoints.",
            evidence=mdns,
            recommendation="Stop-Service 'Bonjour Service'; Set-Service 'Bonjour Service' -StartupType Disabled (if present and unused).",
        ))

    rc, out, _ = run_powershell(
        "(Get-Service -Name Spooler -ErrorAction SilentlyContinue) | Select-Object Name,Status,StartType | Format-List | Out-String"
    )
    spool = (out or "").strip()
    if "Running" in spool:
        findings.append(Finding(
            name="Print Spooler service running",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="The Print Spooler is the service behind PrintNightmare (CVE-2021-34527) and a recurring source of RCE/LPE bugs. Microsoft recommends disabling on machines that don't print (DCs especially).",
            evidence=spool,
            recommendation="Stop-Service Spooler; Set-Service Spooler -StartupType Disabled (on servers and print-less endpoints).",
        ))

    rc, out, _ = run_powershell(
        "(Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindows-PowerShellV2Root' -ErrorAction SilentlyContinue).State; "
        "(Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindows-PowerShellV2' -ErrorAction SilentlyContinue).State"
    )
    psv2 = (out or "")
    if "Enabled" in psv2:
        findings.append(Finding(
            name="PowerShell v2 engine enabled",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="PowerShell v2 bypasses modern security (no AMSI, no script-block logging, no constrained language). Attackers downgrade with `powershell -v 2` to evade detection.",
            evidence=truncate(psv2),
            recommendation="Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2,MicrosoftWindowsPowerShellV2Root",
        ))
    else:
        findings.append(Finding(
            name="PowerShell v2 engine disabled",
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=truncate(psv2),
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -ErrorAction SilentlyContinue; "
        "'Enabled=' + $p.Enabled"
    )
    wsh = (out or "").strip()
    if "Enabled=0" not in wsh:
        findings.append(Finding(
            name="Windows Script Host enabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="WSH runs .vbs / .js scripts — a heavily abused channel for phishing payloads. Most enterprise endpoints don't need it.",
            evidence=wsh,
            recommendation="Set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled = 0 (DWORD). Test for breakage on admin scripts first.",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -ErrorAction SilentlyContinue; "
        "'NoDriveTypeAutoRun=' + $p.NoDriveTypeAutoRun + '|NoAutoRun=' + $p.NoAutoRun"
    )
    ar = (out or "").strip()
    if "NoDriveTypeAutoRun=255" not in ar and "NoDriveTypeAutoRun=0xFF" not in ar:
        findings.append(Finding(
            name="AutoRun / AutoPlay not fully disabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Without NoDriveTypeAutoRun=0xFF, inserting a malicious USB can silently execute autorun.inf payloads.",
            evidence=ar,
            recommendation="Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun = 0xFF (DWORD).",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -ErrorAction SilentlyContinue; "
        "'HideFileExt=' + $p.HideFileExt"
    )
    hfe = (out or "").strip()
    if "HideFileExt=1" in hfe:
        findings.append(Finding(
            name="File extensions hidden in Explorer",
            status=Status.WARN,
            severity=Severity.LOW,
            description="Hiding extensions is social-engineering bait — 'invoice.pdf.exe' appears as 'invoice.pdf'.",
            evidence=hfe,
            recommendation="Set HKCU\\...\\Advanced\\HideFileExt = 0.",
        ))

    rc, out, _ = run_powershell(
        "try { (Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Select-Object Name,Enabled | Format-Table | Out-String) } catch { '' }"
    )
    ip6 = (out or "").strip()
    if ip6 and "False" in ip6 and "True" not in ip6:
        findings.append(Finding(
            name="IPv6 disabled on all adapters",
            status=Status.WARN,
            severity=Severity.LOW,
            description="Disabling IPv6 is an unsupported configuration per Microsoft and can cause subtle issues. Prefer to leave it on and filter with the firewall.",
            evidence=truncate(ip6),
            recommendation="Re-enable IPv6 binding and instead block rogue RA/DHCPv6 with firewall rules and switch-level RA guard.",
        ))

    return findings
