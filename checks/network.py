from .runner import Finding, Severity, Status, run_powershell, truncate

RISKY_PORTS = {
    21: ("FTP", Severity.HIGH, "FTP transmits credentials in clear text."),
    23: ("Telnet", Severity.CRITICAL, "Telnet transmits everything — including the password — in clear text."),
    25: ("SMTP", Severity.MEDIUM, "Open SMTP relays have been abused historically — verify listener is authenticated."),
    69: ("TFTP", Severity.HIGH, "TFTP has no authentication."),
    111: ("RPCbind", Severity.HIGH, "Portmapper enumeration exposes RPC services."),
    135: ("MS RPC endpoint mapper", Severity.MEDIUM, "Should not be exposed beyond trusted networks."),
    137: ("NetBIOS name", Severity.HIGH, "NetBIOS is a common pivot point."),
    138: ("NetBIOS datagram", Severity.HIGH, "NetBIOS is a common pivot point."),
    139: ("NetBIOS SMB", Severity.HIGH, "Legacy NetBIOS-over-TCP SMB path."),
    445: ("SMB", Severity.HIGH, "SMB has hosted several wormable CVEs (EternalBlue, SMBGhost). Should never be exposed to untrusted networks."),
    512: ("rexec", Severity.CRITICAL, "Legacy Unix r-services — clear text, trivially abused."),
    513: ("rlogin", Severity.CRITICAL, "Legacy Unix r-services — clear text."),
    514: ("rsh/syslog", Severity.HIGH, ""),
    1433: ("MSSQL", Severity.HIGH, "Database port should not be exposed publicly."),
    1434: ("MSSQL browser", Severity.HIGH, "MSSQL browser is UDP-discoverable and leaks instance info."),
    3306: ("MySQL", Severity.HIGH, "Database port should not be exposed publicly."),
    3389: ("RDP", Severity.HIGH, "RDP is the single most common ransomware entry vector. Expose only via VPN or with MFA + NLA + account lockout."),
    5985: ("WinRM HTTP", Severity.MEDIUM, "Unencrypted WinRM channel — prefer 5986 (HTTPS)."),
    5900: ("VNC", Severity.HIGH, "VNC often ships with weak or no authentication."),
}


def run():
    findings = []

    rc, tcp_out, err = run_powershell(
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | "
        "Sort-Object LocalPort -Unique | "
        "Format-Table -AutoSize | Out-String -Width 300"
    )
    tcp_text = tcp_out or ""
    findings.append(Finding(
        name="Listening TCP endpoints",
        status=Status.INFO,
        severity=Severity.INFO,
        description="All TCP sockets in LISTEN state.",
        evidence=truncate(tcp_text, 4000),
    ))

    rc, procmap_out, _ = run_powershell(
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | ForEach-Object { "
        "$p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
        "$name = if ($p) { $p.Name } else { '?' }; "
        "\"$($_.LocalAddress)|$($_.LocalPort)|$($_.OwningProcess)|$name\" "
        "}"
    )
    listen_entries = []
    for line in (procmap_out or "").splitlines():
        parts = line.split("|")
        if len(parts) == 4:
            addr, port, pid, name = parts
            try:
                listen_entries.append((addr.strip(), int(port.strip()), pid.strip(), name.strip()))
            except ValueError:
                continue

    public_listeners = [e for e in listen_entries if e[0] in ("0.0.0.0", "::", "*") and not _localonly(e[0])]

    risky_hits = {}
    for addr, port, pid, name in listen_entries:
        if port in RISKY_PORTS and addr in ("0.0.0.0", "::", "*"):
            risky_hits.setdefault(port, []).append(f"{addr}:{port} pid={pid} ({name})")

    for port, entries in risky_hits.items():
        label, sev, desc = RISKY_PORTS[port]
        findings.append(Finding(
            name=f"Risky port open: {port} ({label})",
            status=Status.FAIL,
            severity=sev,
            description=desc or f"{label} listening on all interfaces.",
            evidence="\n".join(entries),
            recommendation=f"If the service isn't required, stop and disable it. If it is, scope firewall rules to specific source IPs / VPN and require encryption/MFA.",
        ))

    if public_listeners and not risky_hits:
        sample = "\n".join(f"{a}:{p} pid={pid} ({n})" for a, p, pid, n in public_listeners[:30])
        findings.append(Finding(
            name=f"{len(public_listeners)} services listening on all interfaces",
            status=Status.INFO,
            severity=Severity.LOW,
            description="Every 0.0.0.0/:: listener is reachable on every network the host joins.",
            evidence=sample,
            recommendation="Bind services to 127.0.0.1 where remote access isn't required.",
        ))

    rc, smb_out, _ = run_powershell(
        "$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol; "
        "$smb2 = (Get-SmbServerConfiguration).EnableSMB2Protocol; "
        "$sign = (Get-SmbServerConfiguration).RequireSecuritySignature; "
        "\"SMB1=$smb1|SMB2=$smb2|Signing=$sign\""
    )
    smb = (smb_out or "").strip()
    if "SMB1=True" in smb:
        findings.append(Finding(
            name="SMBv1 protocol enabled",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="SMBv1 is the protocol behind EternalBlue (MS17-010) and WannaCry. Microsoft has deprecated and removed it from modern Windows by default.",
            evidence=smb,
            recommendation="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
        ))
    elif "SMB1=" in smb:
        findings.append(Finding(
            name="SMBv1 disabled",
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=smb,
        ))

    if "Signing=False" in smb:
        findings.append(Finding(
            name="SMB signing not required",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Without required signing, SMB traffic is susceptible to NTLM relay attacks.",
            evidence=smb,
            recommendation="Set-SmbServerConfiguration -RequireSecuritySignature $true",
        ))

    rc, rdp_out, _ = run_powershell(
        "$deny = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections; "
        "$nla  = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication; "
        "$sec  = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).SecurityLayer; "
        "\"Deny=$deny|NLA=$nla|SecurityLayer=$sec\""
    )
    rdp = (rdp_out or "").strip()
    if "Deny=0" in rdp:
        if "NLA=0" in rdp:
            findings.append(Finding(
                name="RDP enabled without Network Level Authentication",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="Without NLA, RDP accepts a full session connection before authenticating, exposing the host to pre-auth vulnerabilities (BlueKeep etc.).",
                evidence=rdp,
                recommendation="Set UserAuthentication = 1 under HKLM\\...\\RDP-Tcp, or via Group Policy 'Require NLA'.",
            ))
        else:
            findings.append(Finding(
                name="RDP enabled (NLA on)",
                status=Status.INFO,
                severity=Severity.LOW,
                description="RDP is on — ensure firewall restricts source IPs and MFA is enforced upstream if reachable externally.",
                evidence=rdp,
            ))
    elif "Deny=1" in rdp:
        findings.append(Finding(
            name="RDP disabled",
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=rdp,
        ))

    rc, winrm_out, _ = run_powershell(
        "try { (Get-Service WinRM).Status.ToString() } catch { 'ERR' }"
    )
    winrm = (winrm_out or "").strip()
    if winrm == "Running":
        findings.append(Finding(
            name="WinRM service running",
            status=Status.INFO,
            severity=Severity.LOW,
            description="WinRM enables remote PowerShell/management — verify it's intended and that only HTTPS (5986) is exposed.",
            evidence=f"WinRM = {winrm}",
        ))

    rc, proto_out, _ = run_powershell(
        "$paths = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server',"
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server',"
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server',"
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server'; "
        "foreach ($p in $paths) { $e = (Get-ItemProperty -Path $p -Name Enabled -ErrorAction SilentlyContinue).Enabled; "
        "$d = (Get-ItemProperty -Path $p -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault; "
        "\"$p :: Enabled=$e DisabledByDefault=$d\" }"
    )
    proto_text = proto_out or ""
    weak = []
    for line in proto_text.splitlines():
        if "Enabled=1" in line and "Enabled=$null" not in line:
            weak.append(line.strip())
    if weak:
        findings.append(Finding(
            name="Weak TLS/SSL protocol enabled",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="SSL 2.0/3.0 and TLS 1.0/1.1 have known cryptographic weaknesses.",
            evidence="\n".join(weak),
            recommendation="Set Enabled=0 and DisabledByDefault=1 for each weak protocol under SCHANNEL\\Protocols.",
        ))

    return findings


def _localonly(addr: str) -> bool:
    return addr.startswith("127.") or addr == "::1"
