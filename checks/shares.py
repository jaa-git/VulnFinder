from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-SmbShare | Select-Object Name,Path,Description,ScopeName,CurrentUsers,ShareState | "
        "Format-Table -AutoSize | Out-String -Width 300"
    )
    text = out or ""
    findings.append(Finding(
        name="SMB shares",
        status=Status.INFO,
        severity=Severity.INFO,
        evidence=truncate(text or err),
    ))

    rc, nonadmin_out, _ = run_powershell(
        "Get-SmbShare | Where-Object { $_.Name -notmatch '\\$$' -and $_.Name -notin @('print$') } | "
        "Select-Object Name,Path | Format-Table -AutoSize | Out-String"
    )
    non_admin = (nonadmin_out or "").strip()
    lines = [l for l in non_admin.splitlines() if l.strip() and not l.strip().startswith("----") and l.strip() not in ("Name Path", "Name  Path")]
    if len(lines) > 1:
        rc, access_out, _ = run_powershell(
            "Get-SmbShare | Where-Object { $_.Name -notmatch '\\$$' } | ForEach-Object { "
            "$name = $_.Name; "
            "Get-SmbShareAccess -Name $name -ErrorAction SilentlyContinue | "
            "ForEach-Object { \"$name | $($_.AccountName) | $($_.AccessControlType) | $($_.AccessRight)\" } "
            "}"
        )
        access_text = access_out or ""
        wide_open = [l for l in access_text.splitlines() if "Everyone" in l and "Allow" in l]
        if wide_open:
            findings.append(Finding(
                name="SMB share granted to 'Everyone'",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description="A share permission granting 'Everyone' allows any authenticated — and, with legacy configs, unauthenticated — user to access it over the network.",
                evidence="\n".join(wide_open),
                recommendation="Grant-SmbShareAccess with scoped principals (e.g. specific AD groups) and revoke 'Everyone'.",
            ))
        else:
            findings.append(Finding(
                name="Non-admin shares present",
                status=Status.INFO,
                severity=Severity.LOW,
                description="Custom shares exist — verify the ACLs match the data sensitivity.",
                evidence=truncate(non_admin + "\n---\n" + access_text, 3000),
            ))

    rc, anon_out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -ErrorAction SilentlyContinue; "
        "\"NullSessionShares=$($p.NullSessionShares)|RestrictNullSessAccess=$($p.RestrictNullSessAccess)\""
    )
    anon = (anon_out or "").strip()
    if "RestrictNullSessAccess=0" in anon:
        findings.append(Finding(
            name="Null session access to shares permitted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="RestrictNullSessAccess=0 allows anonymous connections to enumerate shares and named pipes.",
            evidence=anon,
            recommendation="Set RestrictNullSessAccess = 1 under HKLM\\...\\LanmanServer\\Parameters.",
        ))

    return findings
