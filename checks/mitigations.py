"""Exploit mitigations: HVCI, DEP, ASLR, Kernel DMA protection, Exploit Guard."""

from .runner import Finding, Severity, Status, run_powershell, truncate


def run():
    findings = []

    rc, out, _ = run_powershell(
        "$g = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue; "
        "if ($g) { "
        "'VBS_Running=' + ($g.VirtualizationBasedSecurityStatus) + '|'"
        "+ 'ServicesConfigured=' + (($g.SecurityServicesConfigured) -join ',') + '|'"
        "+ 'ServicesRunning=' + (($g.SecurityServicesRunning) -join ',') + '|'"
        "+ 'CodeIntegrityPolicy=' + ($g.CodeIntegrityPolicyEnforcementStatus) + '|'"
        "+ 'UMCI=' + ($g.UsermodeCodeIntegrityPolicyEnforcementStatus) "
        "} else { 'ABSENT' }"
    )
    dg = (out or "").strip()
    findings.append(Finding(
        name="Device Guard / VBS status",
        status=Status.INFO,
        severity=Severity.INFO,
        description="VBS underpins HVCI and Credential Guard — hypervisor-backed isolation. "
                    "ServicesRunning codes: 1=CredentialGuard, 2=HVCI, 3=SystemGuard.",
        evidence=dg,
    ))

    running_hvci = "ServicesRunning=" in dg and "2" in dg.split("ServicesRunning=", 1)[1].split("|", 1)[0]
    if not running_hvci:
        findings.append(Finding(
            name="HVCI (memory integrity) not running",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Hypervisor-protected Code Integrity blocks loading of unsigned kernel drivers and protects kernel memory. Core modern defence against kernel-mode malware.",
            evidence=dg,
            recommendation="Enable via Windows Security > Device security > Core isolation > Memory integrity (or GPO). Requires compatible drivers.",
        ))

    running_cg = "ServicesRunning=" in dg and "1" in dg.split("ServicesRunning=", 1)[1].split("|", 1)[0]
    if not running_cg:
        findings.append(Finding(
            name="Credential Guard not running (VBS)",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Credential Guard isolates LSA secrets from the OS, blocking credential theft even from SYSTEM.",
            evidence=dg,
            recommendation="Enable via GPO: Computer > Admin Templates > System > Device Guard > Turn On Virtualization Based Security, with Credential Guard set to Enabled with UEFI lock.",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ProcessMitigation -System -ErrorAction SilentlyContinue; "
        "if ($p) { "
        "'DEP=' + $p.Dep.Enable + '|ASLR_ForceRelocate=' + $p.Aslr.ForceRelocateImages + '|ASLR_Bottom=' + $p.Aslr.BottomUp + '|ASLR_High=' + $p.Aslr.HighEntropy + '|CFG=' + $p.Cfg.Enable + '|SEHOP=' + $p.SEHOP.Enable "
        "} else { 'ABSENT' }"
    )
    em = (out or "").strip()
    findings.append(Finding(
        name="System-wide process mitigations",
        status=Status.INFO,
        severity=Severity.INFO,
        description="System defaults for DEP, ASLR, Control Flow Guard and SEHOP.",
        evidence=em,
    ))
    issues = []
    if "DEP=ON" not in em and "DEP=NOTSET" not in em and em != "ABSENT":
        issues.append("DEP not ON")
    if "ASLR_ForceRelocate=ON" not in em and em != "ABSENT":
        issues.append("ASLR ForceRelocateImages not ON (non-/DYNAMICBASE binaries not relocated)")
    if "ASLR_Bottom=ON" not in em and em != "ABSENT":
        issues.append("ASLR BottomUp not ON")
    if "CFG=ON" not in em and "CFG=NOTSET" not in em and em != "ABSENT":
        issues.append("Control Flow Guard not ON")
    if issues:
        findings.append(Finding(
            name=f"Weak exploit mitigations: {len(issues)}",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="System-wide mitigation defaults are weaker than the Microsoft baseline.",
            evidence=em + "\n" + "\n".join(issues),
            recommendation="Set via Windows Security > App & browser control > Exploit protection > System settings, or with Set-ProcessMitigation.",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\AllowedBuses' -ErrorAction SilentlyContinue; "
        "$k = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\KernelDmaProtection' -ErrorAction SilentlyContinue; "
        "'ThunderboltDMA=' + (msinfo32.exe /report nul 2>$null; 'see msinfo32') "
    )
    rc, out2, _ = run_powershell(
        "$sys = Get-CimInstance Win32_ComputerSystem; "
        "'BootDMAProtection=' + (systeminfo 2>$null | Select-String 'Hyper-V')"
    )
    rc, out3, _ = run_powershell(
        "(Get-CimInstance -Namespace root\\cimv2\\mdm\\dmmap -ClassName MDM_Policy_Result01_DataProtection02 -ErrorAction SilentlyContinue | "
        "Select-Object AllowDirectMemoryAccess | Format-List | Out-String)"
    )
    dma_blob = "\n".join(x for x in [out, out2, out3] if x and x.strip())
    if dma_blob.strip():
        findings.append(Finding(
            name="Kernel DMA protection (info)",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Kernel DMA protection blocks rogue PCIe/Thunderbolt devices from reading memory at boot or runtime. Check msinfo32 > System Summary > 'Kernel DMA Protection'.",
            evidence=truncate(dma_blob, 1500),
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue; "
        "'LocalAccountTokenFilterPolicy=' + $p.LocalAccountTokenFilterPolicy"
    )
    ltf = (out or "").strip()
    if "LocalAccountTokenFilterPolicy=1" in ltf:
        findings.append(Finding(
            name="LocalAccountTokenFilterPolicy = 1 (UAC remote restrictions disabled)",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Setting this to 1 allows local admin accounts to perform remote administrative operations (pass-the-hash over SMB/WMI), defeating UAC's remote token filtering.",
            evidence=ltf,
            recommendation="Delete the value or set it to 0.",
        ))

    rc, out, _ = run_powershell(
        "$p = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -ErrorAction SilentlyContinue; "
        "if ($p) { 'VulnerableDriverBlocklistEnable=' + $p.VulnerableDriverBlocklistEnable } else { 'ABSENT' }"
    )
    drvbl = (out or "").strip()
    if "VulnerableDriverBlocklistEnable=1" not in drvbl:
        findings.append(Finding(
            name="Microsoft vulnerable-driver blocklist not enabled",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Windows ships with a blocklist of known-vulnerable drivers used in BYOVD (bring-your-own-vulnerable-driver) attacks. On by default on Win11, not always on Win10.",
            evidence=drvbl,
            recommendation="Enable via Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist.",
        ))

    return findings
