"""Credential-handling hardening: NTLM, LM, WDigest, cached logons, restricted admin."""

from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -ErrorAction SilentlyContinue; "
        "if ($p) { 'UseLogonCredential=' + $p.UseLogonCredential } else { 'KEY_ABSENT' }"
    )
    w = (out or "").strip()
    if "UseLogonCredential=1" in w:
        findings.append(Finding(
            name="WDigest plain-text credential caching enabled",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="UseLogonCredential=1 causes LSASS to hold plain-text passwords in memory — exactly what mimikatz harvests. No modern Windows should have this set.",
            evidence=w,
            recommendation="Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0 (DWORD) and reboot.",
        ))
    else:
        findings.append(Finding(
            name="WDigest plain-text caching disabled",
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=w,
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue; "
        "'LMCompatibilityLevel=' + $p.LmCompatibilityLevel"
    )
    line = (out or "").strip()
    m = None
    for token in line.split():
        if token.isdigit():
            m = int(token)
            break
    if line.endswith("="):  # key absent
        findings.append(Finding(
            name="LMCompatibilityLevel not configured",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="When unset, Windows defaults vary and may accept NTLMv1.",
            evidence=line,
            recommendation="Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel = 5 (Send NTLMv2 only, refuse LM & NTLM).",
        ))
    elif m is not None and m < 3:
        findings.append(Finding(
            name=f"LMCompatibilityLevel={m} — LM/NTLMv1 accepted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Levels below 3 accept or send LM / NTLMv1 hashes, which are crackable in seconds.",
            evidence=line,
            recommendation="Set LmCompatibilityLevel = 5 via GPO or registry.",
        ))
    elif m is not None:
        findings.append(Finding(
            name=f"LMCompatibilityLevel={m}",
            status=Status.PASS if m >= 5 else Status.INFO,
            severity=Severity.INFO,
            evidence=line,
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue; "
        "'CachedLogonsCount=' + $p.CachedLogonsCount"
    )
    c_line = (out or "").strip()
    cnum = None
    for t in c_line.split("="):
        t = t.strip()
        if t.isdigit():
            cnum = int(t)
    if cnum is not None and cnum > 10:
        findings.append(Finding(
            name=f"CachedLogonsCount is {cnum}",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Windows caches the last N domain logons (salted MSCash hashes). Larger caches mean more credentials to harvest with SYSTEM access.",
            evidence=c_line,
            recommendation="Set CachedLogonsCount = 2 (laptops) or 0 (desktops on stable networks).",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -ErrorAction SilentlyContinue; "
        "'NtlmMinClientSec=' + $p.NtlmMinClientSec + '|NtlmMinServerSec=' + $p.NtlmMinServerSec + "
        "'|RestrictSendingNTLMTraffic=' + $p.RestrictSendingNTLMTraffic + '|RestrictReceivingNTLMTraffic=' + $p.RestrictReceivingNTLMTraffic"
    )
    ntlm_line = (out or "").strip()
    if "RestrictSendingNTLMTraffic=" in ntlm_line and not _nonempty_after(ntlm_line, "RestrictSendingNTLMTraffic="):
        findings.append(Finding(
            name="NTLM outgoing traffic not restricted",
            status=Status.WARN,
            severity=Severity.LOW,
            description="Restricting outgoing NTLM reduces exposure to NTLM relay. 1 = audit, 2 = deny except allow-list.",
            evidence=ntlm_line,
            recommendation="Consider setting RestrictSendingNTLMTraffic = 1 (audit) first, then = 2.",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue; "
        "'DisableRestrictedAdmin=' + $p.DisableRestrictedAdmin + '|DisableRestrictedAdminOutboundCreds=' + $p.DisableRestrictedAdminOutboundCreds"
    )
    ra_line = (out or "").strip()
    findings.append(Finding(
        name="RestrictedAdmin / outbound credential settings",
        status=Status.INFO,
        severity=Severity.INFO,
        description="RestrictedAdmin mode for RDP and outbound creds policy affect how credentials traverse remote sessions.",
        evidence=ra_line,
    ))

    rc, out, _ = run_powershell(
        "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\*' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.PSChildName -like '*-*' -and (Get-ItemProperty $_.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath -like '*mimikatz*' } | "
        "Select-Object -First 5 PSChildName | Out-String"
    )
    if (out or "").strip():
        findings.append(Finding(
            name="Service path matches 'mimikatz'",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="A service is configured with an image path containing 'mimikatz'. Strongly suggests a compromise or offensive-security test left behind.",
            evidence=truncate(out),
            recommendation="Stop and remove the service; investigate the host for further indicators of compromise.",
        ))

    return findings


def _nonempty_after(s: str, key: str) -> bool:
    idx = s.find(key)
    if idx < 0:
        return False
    rest = s[idx + len(key):]
    end = rest.find("|")
    val = (rest if end < 0 else rest[:end]).strip()
    return val not in ("", "0")
