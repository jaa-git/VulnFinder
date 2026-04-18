from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-MpComputerStatus | Format-List | Out-String"
    )
    text = out or ""
    if not text.strip():
        findings.append(Finding(
            name="Defender status unavailable",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Get-MpComputerStatus returned no data — Defender may be disabled, replaced by third-party AV, or blocked by policy.",
            evidence=truncate(err),
            recommendation="Verify an antivirus is active via Security Center: Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct",
        ))
        _third_party(findings)
        return findings

    checks = {
        "RealTimeProtectionEnabled": ("Real-time protection", Severity.CRITICAL),
        "AntivirusEnabled": ("Antivirus engine", Severity.CRITICAL),
        "AntispywareEnabled": ("Antispyware engine", Severity.HIGH),
        "BehaviorMonitorEnabled": ("Behavior monitoring", Severity.HIGH),
        "IoavProtectionEnabled": ("IOAV (downloaded files) scanning", Severity.HIGH),
        "OnAccessProtectionEnabled": ("On-access protection", Severity.HIGH),
        "NISEnabled": ("Network Inspection System", Severity.MEDIUM),
        "IsTamperProtected": ("Tamper protection", Severity.HIGH),
    }
    for key, (label, sev) in checks.items():
        value = _extract(text, key)
        if value is None:
            continue
        if value.lower() == "true":
            findings.append(Finding(
                name=f"{label}: enabled",
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=f"{key} = {value}",
            ))
        else:
            findings.append(Finding(
                name=f"{label}: DISABLED",
                status=Status.FAIL,
                severity=sev,
                description=f"{label} is a core Defender protection component. Disabling it removes a primary malware detection layer.",
                evidence=f"{key} = {value}",
                recommendation=f"Re-enable via Group Policy / Intune / Set-MpPreference. Check whether a third-party AV has taken over.",
            ))

    sig_age = _extract(text, "AntivirusSignatureAge")
    if sig_age and sig_age.isdigit():
        age = int(sig_age)
        if age > 7:
            findings.append(Finding(
                name=f"Antivirus signatures are {age} days old",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="Stale signatures leave the endpoint blind to recent malware families.",
                evidence=f"AntivirusSignatureAge = {age}",
                recommendation="Run: Update-MpSignature. Investigate why Windows Update / WSUS is not delivering definitions.",
            ))
        elif age > 2:
            findings.append(Finding(
                name=f"Antivirus signatures are {age} days old",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                evidence=f"AntivirusSignatureAge = {age}",
                recommendation="Run Update-MpSignature.",
            ))
        else:
            findings.append(Finding(
                name="Antivirus signatures up to date",
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=f"AntivirusSignatureAge = {age} days",
            ))

    rc, asr_out, _ = run_powershell(
        "$p = Get-MpPreference; "
        "$ids = $p.AttackSurfaceReductionRules_Ids; "
        "$acts = $p.AttackSurfaceReductionRules_Actions; "
        "if (-not $ids) { 'NONE' } else { for ($i=0; $i -lt $ids.Count; $i++) { \"$($ids[$i])=$($acts[$i])\" } }"
    )
    asr_text = (asr_out or "").strip()
    if asr_text == "NONE" or not asr_text:
        findings.append(Finding(
            name="No Attack Surface Reduction rules configured",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="ASR rules block common post-exploitation techniques (Office macro abuse, LSASS theft, WMI persistence, etc.) — they're one of the highest-value defensive controls on Windows.",
            evidence="AttackSurfaceReductionRules_Ids is empty.",
            recommendation="Enable the baseline ASR rules, at minimum: block credential theft from LSASS (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2).",
        ))
    else:
        disabled = [l for l in asr_text.splitlines() if l.endswith("=0")]
        enabled = [l for l in asr_text.splitlines() if l.endswith("=1") or l.endswith("=6")]
        if disabled:
            findings.append(Finding(
                name="Some ASR rules set to Disabled",
                status=Status.WARN,
                severity=Severity.LOW,
                evidence=asr_text,
                recommendation="Review each rule — Block (1) is preferred, Audit (2) for evaluation only.",
            ))
        if enabled:
            findings.append(Finding(
                name=f"ASR rules active: {len(enabled)}",
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=asr_text,
            ))

    rc, cfa_out, _ = run_powershell(
        "(Get-MpPreference).EnableControlledFolderAccess"
    )
    cfa = (cfa_out or "").strip()
    if cfa == "0":
        findings.append(Finding(
            name="Controlled Folder Access disabled",
            status=Status.WARN,
            severity=Severity.LOW,
            description="CFA blocks ransomware-style writes to user document folders from untrusted processes.",
            evidence=f"EnableControlledFolderAccess = {cfa}",
            recommendation="Set-MpPreference -EnableControlledFolderAccess Enabled (validate with audit mode first).",
        ))

    _third_party(findings)
    return findings


def _third_party(findings):
    rc, out, _ = run_powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | "
        "Select-Object displayName,productState,pathToSignedProductExe | Format-List | Out-String"
    )
    if (out or "").strip():
        findings.append(Finding(
            name="Registered antivirus products",
            status=Status.INFO,
            severity=Severity.INFO,
            description="All antivirus products registered with Windows Security Center.",
            evidence=truncate(out),
        ))


def _extract(text: str, key: str):
    for line in text.splitlines():
        if line.strip().startswith(key):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None
