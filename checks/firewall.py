from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName | Format-List | Out-String"
    )
    text = out or ""
    findings.append(Finding(
        name="Firewall profiles — raw",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Full configuration of the Domain, Private and Public firewall profiles.",
        evidence=truncate(text or err),
    ))

    rc, enabled_out, _ = run_powershell(
        "Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.Enabled } | Out-String"
    )
    lines = [l.strip() for l in (enabled_out or "").splitlines() if l.strip()]
    disabled = [l for l in lines if l.lower().endswith("=false")]
    if disabled:
        findings.append(Finding(
            name="Firewall disabled on one or more profiles",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="The Windows Defender Firewall is the host's main inbound attack boundary. A disabled profile exposes all listening services on networks matching that profile.",
            evidence="\n".join(lines),
            recommendation="Enable all three profiles: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
        ))
    else:
        findings.append(Finding(
            name="Firewall enabled on all profiles",
            status=Status.PASS,
            severity=Severity.INFO,
            description="Domain, Private and Public profiles are all enabled.",
            evidence="\n".join(lines),
        ))

    rc, inbound_out, _ = run_powershell(
        "Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.DefaultInboundAction } | Out-String"
    )
    bad = [l for l in (inbound_out or "").splitlines() if l.strip() and "Allow" in l]
    if bad:
        findings.append(Finding(
            name="Default inbound action is Allow",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="A default-allow posture means any port not explicitly blocked is reachable. Should be Block.",
            evidence="\n".join(bad),
            recommendation="Set-NetFirewallProfile -Profile <name> -DefaultInboundAction Block",
        ))
    else:
        findings.append(Finding(
            name="Default inbound action is Block",
            status=Status.PASS,
            severity=Severity.INFO,
            description="Default-deny inbound on all profiles.",
            evidence=truncate(inbound_out),
        ))

    rc, rules_out, _ = run_powershell(
        "(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Measure-Object).Count"
    )
    count = (rules_out or "").strip()
    if count.isdigit() and int(count) > 0:
        rc, sample, _ = run_powershell(
            "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
            "Select-Object -First 25 DisplayName,Profile,Action | Format-Table -AutoSize | Out-String"
        )
        findings.append(Finding(
            name=f"Inbound allow rules enabled: {count}",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Each enabled inbound allow rule widens the attack surface. Review and disable any you do not need.",
            evidence=truncate(sample, 3000),
            recommendation="Audit with: Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Out-GridView",
        ))

    return findings
