from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "try { Get-BitLockerVolume | Select-Object MountPoint,VolumeType,ProtectionStatus,EncryptionMethod,VolumeStatus,EncryptionPercentage,LockStatus | Format-Table -AutoSize | Out-String } catch { $_.Exception.Message }"
    )
    text = (out or "").strip()
    if not text or "is not recognized" in text or "ObjectNotFound" in text:
        findings.append(Finding(
            name="BitLocker cmdlets unavailable",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Get-BitLockerVolume is not available. Either the BitLocker feature is not installed (Windows Home) or the command was denied.",
            evidence=truncate(text or err),
            recommendation="On Pro/Enterprise, install BitLocker and encrypt the OS volume. On Home, use Device Encryption (Settings > Privacy & security > Device encryption).",
        ))
        rc, dev_out, _ = run_powershell(
            "(Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue | "
            "Select-Object DriveLetter,ProtectionStatus,ConversionStatus | Format-Table -AutoSize | Out-String)"
        )
        if (dev_out or "").strip():
            findings.append(Finding(
                name="Encryptable volumes (raw WMI)",
                status=Status.INFO,
                severity=Severity.INFO,
                evidence=truncate(dev_out),
            ))
        return findings

    findings.append(Finding(
        name="BitLocker status (all volumes)",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=truncate(text),
    ))

    rc, osvol_out, _ = run_powershell(
        "$sys = $env:SystemDrive; "
        "$v = Get-BitLockerVolume -MountPoint $sys -ErrorAction SilentlyContinue; "
        "if ($v) { \"$($v.MountPoint)|$($v.ProtectionStatus)|$($v.VolumeStatus)|$($v.EncryptionMethod)|$($v.EncryptionPercentage)\" }"
    )
    line = (osvol_out or "").strip()
    if "|" in line:
        mp, prot, vstat, method, pct = line.split("|")
        if prot != "On":
            findings.append(Finding(
                name=f"OS volume ({mp}) not BitLocker-protected",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description="An unencrypted OS disk exposes all data — including SAM hashes, cached credentials and DPAPI keys — to anyone with brief physical access.",
                evidence=line,
                recommendation="Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -TpmProtector; Add-BitLockerKeyProtector -RecoveryPasswordProtector. Back up the recovery key to AD/Entra.",
            ))
        elif vstat != "FullyEncrypted":
            findings.append(Finding(
                name=f"OS volume encryption not complete ({pct}%)",
                status=Status.WARN,
                severity=Severity.HIGH,
                evidence=line,
            ))
        else:
            findings.append(Finding(
                name="OS volume fully encrypted with BitLocker",
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=line,
            ))

        if "Aes128" in method:
            findings.append(Finding(
                name="BitLocker encryption method is AES-128",
                status=Status.WARN,
                severity=Severity.LOW,
                description="XtsAes256 is the current Microsoft-recommended cipher for fixed OS volumes.",
                evidence=f"EncryptionMethod = {method}",
                recommendation="Decrypt and re-encrypt with -EncryptionMethod XtsAes256.",
            ))

    rc, prot_out, _ = run_powershell(
        "$sys = $env:SystemDrive; "
        "Get-BitLockerVolume -MountPoint $sys -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty KeyProtector | "
        "Select-Object KeyProtectorType,KeyProtectorId | Format-Table | Out-String"
    )
    ptxt = prot_out or ""
    if ptxt.strip():
        findings.append(Finding(
            name="BitLocker key protectors",
            status=Status.INFO,
            severity=Severity.INFO,
            evidence=truncate(ptxt),
        ))
        if "RecoveryPassword" not in ptxt:
            findings.append(Finding(
                name="No RecoveryPassword protector on OS volume",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                description="Without a recovery password, a TPM reset or firmware change can lock users out of their own data permanently.",
                evidence=truncate(ptxt),
                recommendation="Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector and escrow to AD / Entra ID.",
            ))

    return findings
