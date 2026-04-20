# Bastion

Windows 10 / 11 security audit tool. Run it with admin rights and it enumerates misconfigurations and weak posture across firewall, Defender, user accounts, password / lockout policy, BitLocker, updates, open ports, shares and services, then writes a styled PDF report.

## Download

Grab the prebuilt `Bastion.exe` from the [Releases page](../../releases/latest). No Python required — single file, ~28 MB.

## Usage

1. Copy `Bastion.exe` to the target machine.
2. Right-click → **Run as administrator** (the exe also requests UAC elevation automatically).
3. When it finishes, the PDF, scan log and `findings.json` are written to `reports\bastion_<hostname>_<timestamp>\` next to the exe.

### Flags
```
Bastion.exe [-o folder] [--no-pdf] [--quiet] [--offline] [--no-pause]
```
`--offline` skips the online vulnerability feed fetcher.

### Exit codes
- `0` — no criticals / highs
- `1` — one or more HIGH failures
- `2` — one or more CRITICAL failures
- `3` — PDF generation failed (see `error.log` in the run folder)
- `4` — unhandled error (see `error.log`)

## What it checks

| Category | Examples |
|---|---|
| **System** | OS version, Secure Boot, TPM, Credential Guard, Windows 10 EOL |
| **Firewall** | Profile enabled state, default inbound action, enabled allow-rules |
| **Defender / AV** | Real-time, tamper protection, signature age, ASR rules, Controlled Folder Access |
| **Accounts** | Admin group members, Guest, built-in Administrator, PasswordRequired=False, autologon, UAC, LSA protection, LM hashes |
| **Credential Protection** | WDigest plaintext caching, LMCompatibilityLevel, NTLM restrictions, CachedLogonsCount, RestrictedAdmin |
| **Password & Lockout** | Min length, complexity, history, lockout threshold, secedit, audit subcategory coverage |
| **BitLocker** | OS volume protection, encryption cipher, key protectors |
| **Updates** | Hotfix age, WU services, NoAutoUpdate policy |
| **Network** | Listening TCP ports, risky ports (23, 445, 3389 etc.), SMBv1, SMB signing, RDP / NLA, weak SSL/TLS |
| **Name Resolution & Legacy Protocols** | LLMNR, NetBIOS-over-TCP, WPAD, mDNS, Print Spooler, PowerShell v2 engine, Windows Script Host, AutoRun, hidden extensions |
| **Shares** | Everyone ACLs, null session access |
| **Services** | Risky services (Telnet, RemoteRegistry, WebClient...), execution policy, script-block logging, unquoted service paths, autoruns |
| **Installed Software & Tasks** | Full inventory, outdated risky products (Flash, old Java/WinRAR), scheduled tasks running as SYSTEM, unsigned drivers, Office macro policy, processes from Temp, writable PATH entries |
| **Exploit Mitigations** | VBS / HVCI, Credential Guard, DEP, ASLR, CFG, Kernel DMA Protection, LocalAccountTokenFilterPolicy, Microsoft Vulnerable Driver Blocklist |
| **Logging & Visibility** | Event log sizing, PowerShell transcription & module logging, Sysmon, core defence services |
| **Live Vulnerability Advisories** | Pulls `feeds.json` from this repo at scan time and scrapes CISA KEV, MSRC, BleepingComputer, The Hacker News and NVD for current Windows-relevant advisories |

Findings are classified `CRITICAL / HIGH / MEDIUM / LOW / INFO` and each carries an evidence snippet and a remediation command.

## Run folder contents

Every run creates its own subfolder under `reports\`:

```
reports\bastion_<hostname>_<timestamp>\
    report.pdf          # styled audit report
    findings.json       # full machine-readable output
    scan.log            # tee'd stdout/stderr (readable in Notepad)
    error.log           # only written on failure
```

If the exe directory isn't writable (e.g. running from `Program Files`), Bastion falls back to `%USERPROFILE%\Documents\Bastion\` and finally to `%TEMP%\`.

## Adding new advisory sources

The file [`feeds.json`](feeds.json) in this repo is fetched on every scan — edit it to add or remove sources without rebuilding the exe. Supported `type` values: `cisa_kev`, `rss`, `nvd`.

## Building from source

```powershell
pip install -r requirements.txt
python bastion.py              # run directly
build.bat                      # produce dist\Bastion.exe
```

Requires Python 3.11+ on Windows.

## Notes

- The exe is unsigned, so SmartScreen may warn on first run. Click *More info → Run anyway*.
- Some endpoint protection products flag PyInstaller bootloaders. Whitelist the binary or build locally if that happens.
- Most checks need administrator privileges — running unelevated produces a partial report.
