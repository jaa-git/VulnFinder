from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime | "
        "Format-List | Out-String"
    )
    findings.append(Finding(
        name="Operating System",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Basic OS identification for the scanned host.",
        evidence=truncate(out or err),
    ))

    rc, out, err = run_powershell(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Manufacturer,Model,Domain,PartOfDomain,UserName,TotalPhysicalMemory | "
        "Format-List | Out-String"
    )
    findings.append(Finding(
        name="Computer System",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Hardware and domain membership.",
        evidence=truncate(out or err),
    ))

    rc, out, err = run_powershell(
        "Confirm-SecureBootUEFI 2>$null"
    )
    val = (out or "").strip().lower()
    if val == "true":
        findings.append(Finding(
            name="Secure Boot",
            status=Status.PASS,
            severity=Severity.INFO,
            description="Secure Boot prevents loading of unsigned bootloaders and rootkits at boot.",
            evidence="Secure Boot is ENABLED.",
        ))
    elif val == "false":
        findings.append(Finding(
            name="Secure Boot disabled",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Secure Boot is a UEFI feature that blocks unsigned bootloaders and bootkits.",
            evidence="Confirm-SecureBootUEFI returned False.",
            recommendation="Enable Secure Boot in UEFI firmware. Required for Windows 11 compliance.",
        ))
    else:
        findings.append(Finding(
            name="Secure Boot (not UEFI / unknown)",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Secure Boot status could not be determined — likely legacy BIOS boot.",
            evidence=truncate(out + err),
            recommendation="Convert disk to GPT and boot in UEFI mode so Secure Boot can be enabled.",
        ))

    rc, out, err = run_powershell(
        "try { (Get-Tpm).TpmPresent.ToString() + '|' + (Get-Tpm).TpmReady.ToString() + '|' + (Get-Tpm).TpmEnabled.ToString() } catch { 'ERR' }"
    )
    line = (out or "").strip()
    if "|" in line:
        present, ready, enabled = line.split("|")
        if present.lower() == "true" and ready.lower() == "true":
            findings.append(Finding(
                name="TPM present and ready",
                status=Status.PASS,
                severity=Severity.INFO,
                description="TPM underpins BitLocker, Credential Guard and Windows Hello.",
                evidence=f"Present={present} Ready={ready} Enabled={enabled}",
            ))
        else:
            findings.append(Finding(
                name="TPM not ready",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="A working TPM (2.0) is required for BitLocker with hardware binding, Credential Guard and Win11.",
                evidence=f"Present={present} Ready={ready} Enabled={enabled}",
                recommendation="Enable and provision the TPM in UEFI. Clear and re-initialise if stuck in an unready state.",
            ))
    else:
        findings.append(Finding(
            name="TPM query failed",
            status=Status.ERROR,
            severity=Severity.MEDIUM,
            description="Could not query TPM — Get-Tpm requires admin and TPM drivers.",
            evidence=truncate(out + err),
        ))

    rc, out, err = run_powershell(
        "(Get-ComputerInfo -Property DeviceGuardSecurityServicesRunning,DeviceGuardSecurityServicesConfigured | Format-List | Out-String)"
    )
    text = (out or "").strip()
    running_has_cg = "CredentialGuard" in text and "DeviceGuardSecurityServicesRunning" in text and "CredentialGuard" in text.split("DeviceGuardSecurityServicesRunning", 1)[-1]
    if "CredentialGuard" in text:
        findings.append(Finding(
            name="Credential Guard running",
            status=Status.PASS,
            severity=Severity.INFO,
            description="Credential Guard isolates LSA secrets in a VM-based enclave, blocking pass-the-hash.",
            evidence=truncate(text),
        ))
    else:
        findings.append(Finding(
            name="Credential Guard not running",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Without Credential Guard, NTLM hashes and Kerberos tickets in LSASS memory can be harvested by an attacker with SYSTEM.",
            evidence=truncate(text),
            recommendation="Enable Virtualization Based Security and Credential Guard via Group Policy or Intune (requires UEFI + Secure Boot + TPM).",
        ))

    rc, out, _ = run_powershell(
        "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption"
    )
    caption = (out or "").strip()
    if caption and "Windows 10" in caption:
        findings.append(Finding(
            name="Running Windows 10",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Windows 10 mainstream support ended 14 Oct 2025. Without an ESU subscription the device no longer receives security updates.",
            evidence=caption,
            recommendation="Upgrade to Windows 11 or enrol the device in Extended Security Updates (ESU).",
        ))

    return findings
