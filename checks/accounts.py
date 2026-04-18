from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, err = run_powershell(
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordExpires,PasswordLastSet,LastLogon,Description | "
        "Format-Table -AutoSize | Out-String -Width 300"
    )
    text = out or ""
    findings.append(Finding(
        name="Local user accounts",
        status=Status.INFO,
        severity=Severity.INFO,
        description="All local user accounts on the machine.",
        evidence=truncate(text, 4000),
    ))

    rc, admins_out, _ = run_powershell(
        "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,PrincipalSource | "
        "Format-Table -AutoSize | Out-String"
    )
    admins_text = admins_out or ""
    admin_lines = [l for l in admins_text.splitlines() if l.strip() and "ObjectClass" not in l and not l.startswith("-")]
    findings.append(Finding(
        name=f"Administrators group members",
        status=Status.INFO,
        severity=Severity.INFO,
        description="Every account listed here has full administrative control of the machine.",
        evidence=truncate(admins_text),
    ))

    rc, current_out, _ = run_powershell(
        "whoami"
    )
    me = (current_out or "").strip()
    if me:
        rc, is_admin_out, _ = run_powershell(
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        )
        if (is_admin_out or "").strip().lower() == "true":
            findings.append(Finding(
                name="Current user is an administrator",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                description="Daily driver accounts should not hold local admin. A compromised browser, Office doc or installer escalates instantly to full machine control without a UAC prompt.",
                evidence=f"User: {me}",
                recommendation="Create a separate admin account (e.g. 'admin-<initials>') and demote the daily account to Users. Use Run-As / UAC only when needed.",
            ))

    rc, guest_out, _ = run_powershell(
        "$g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; if ($g) { $g.Enabled } else { 'ABSENT' }"
    )
    g = (guest_out or "").strip()
    if g.lower() == "true":
        findings.append(Finding(
            name="Guest account enabled",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="The built-in Guest account allows anonymous-like access with no password and weakens several authentication surfaces (SMB, RDP policies).",
            evidence="Guest.Enabled = True",
            recommendation="Disable-LocalUser -Name Guest",
        ))

    rc, admin_out, _ = run_powershell(
        "$a = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue; "
        "if ($a) { $a.Enabled.ToString() + '|' + $a.PasswordLastSet }"
    )
    a = (admin_out or "").strip()
    if "|" in a:
        enabled, plset = a.split("|", 1)
        if enabled.lower() == "true":
            findings.append(Finding(
                name="Built-in Administrator (RID 500) enabled",
                status=Status.WARN,
                severity=Severity.MEDIUM,
                description="The built-in Administrator is a well-known target for brute-force and exempt from some UAC protections. Prefer a dedicated named admin.",
                evidence=f"Enabled={enabled} PasswordLastSet={plset}",
                recommendation="Disable-LocalUser -Name Administrator and use a named admin account instead.",
            ))

    rc, pwd_out, _ = run_powershell(
        "Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired } | "
        "Select-Object Name,PasswordRequired | Format-Table | Out-String"
    )
    if (pwd_out or "").strip():
        findings.append(Finding(
            name="Enabled accounts without a required password",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Accounts with PasswordRequired=False can log in with no password. Any attacker with network or console access walks in.",
            evidence=truncate(pwd_out),
            recommendation="Set-LocalUser -Name <name> -PasswordNeverExpires $false; assign a strong password.",
        ))

    rc, noexp_out, _ = run_powershell(
        "Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordExpires } | "
        "Select-Object Name | Format-Table | Out-String"
    )
    if (noexp_out or "").strip():
        # Exclude expected ones
        lines = [l.strip() for l in noexp_out.splitlines() if l.strip() and l.strip() not in ("Name", "----")]
        if lines:
            findings.append(Finding(
                name="Accounts with passwords set to never expire",
                status=Status.WARN,
                severity=Severity.LOW,
                description="Non-rotating passwords are only acceptable for break-glass accounts protected by long/complex passphrases and tightly monitored.",
                evidence="\n".join(lines),
                recommendation="Enforce rotation via the AD password policy, or justify each exception.",
            ))

    rc, autologon_out, _ = run_powershell(
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue | "
        "Select-Object AutoAdminLogon,DefaultUserName,DefaultPassword | Format-List | Out-String"
    )
    al = autologon_out or ""
    if "AutoAdminLogon" in al:
        auto_line = [l for l in al.splitlines() if l.strip().startswith("AutoAdminLogon")]
        if auto_line and ("1" in auto_line[0] or "True" in auto_line[0]):
            has_pw = any(l.strip().startswith("DefaultPassword") and ":" in l and l.split(":",1)[1].strip() for l in al.splitlines())
            findings.append(Finding(
                name="AutoAdminLogon enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="AutoAdminLogon logs a user in automatically at boot with no authentication challenge. If DefaultPassword is present, it is stored in the registry in plain text.",
                evidence=truncate(al),
                recommendation="Set AutoAdminLogon = 0 and clear DefaultPassword from HKLM\\...\\Winlogon.",
            ))

    rc, uac_out, _ = run_powershell(
        "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | "
        "Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,FilterAdministratorToken | Format-List | Out-String"
    )
    uac = uac_out or ""
    if "EnableLUA" in uac:
        lua_line = [l for l in uac.splitlines() if l.strip().startswith("EnableLUA")]
        if lua_line and lua_line[0].strip().endswith(": 0"):
            findings.append(Finding(
                name="UAC disabled (EnableLUA=0)",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                description="User Account Control off means every process runs with the full token of whatever user launched it. Admin-equivalent malware has no elevation prompt to defeat.",
                evidence=truncate(uac),
                recommendation="Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1 and reboot.",
            ))
        else:
            consent = [l for l in uac.splitlines() if l.strip().startswith("ConsentPromptBehaviorAdmin")]
            if consent and consent[0].strip().endswith(": 0"):
                findings.append(Finding(
                    name="UAC elevation prompt disabled for admins",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    description="ConsentPromptBehaviorAdmin=0 elevates without a prompt for admins, silently granting full rights to anything an admin runs.",
                    evidence=truncate(uac),
                    recommendation="Set ConsentPromptBehaviorAdmin = 2 (prompt for consent on secure desktop).",
                ))
            else:
                findings.append(Finding(
                    name="UAC enabled",
                    status=Status.PASS,
                    severity=Severity.INFO,
                    evidence=truncate(uac),
                ))

    rc, lsa_out, _ = run_powershell(
        "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue | "
        "Select-Object RunAsPPL,LimitBlankPasswordUse,NoLmHash,RestrictAnonymous,RestrictAnonymousSAM | Format-List | Out-String"
    )
    lsa = lsa_out or ""
    ppl_line = [l for l in lsa.splitlines() if l.strip().startswith("RunAsPPL")]
    if not ppl_line or not (ppl_line[0].strip().endswith(": 1") or ppl_line[0].strip().endswith(": 2")):
        findings.append(Finding(
            name="LSA protection (RunAsPPL) not enabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Without LSA Protected Process Light, tools like mimikatz can read LSASS memory and harvest credentials.",
            evidence=truncate(lsa),
            recommendation="Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 (DWORD) and reboot.",
        ))

    lm_line = [l for l in lsa.splitlines() if l.strip().startswith("NoLmHash")]
    if lm_line and lm_line[0].strip().endswith(": 0"):
        findings.append(Finding(
            name="LM hashes stored (NoLmHash=0)",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="LM hashes are trivially crackable.",
            evidence=truncate(lsa),
            recommendation="Set NoLmHash = 1.",
        ))

    return findings
