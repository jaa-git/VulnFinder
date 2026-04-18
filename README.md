# VulnFinder

Windows 10 / 11 security audit tool. Run it with admin rights and it enumerates misconfigurations and weak posture across firewall, Defender, user accounts, password / lockout policy, BitLocker, updates, open ports, shares and services, then writes a styled PDF report.

## Download

Grab the prebuilt `VulnFinder.exe` from the [Releases page](../../releases/latest). No Python required — single file, ~28 MB.

## Usage

1. Copy `VulnFinder.exe` to the target machine.
2. Right-click → **Run as administrator** (the exe also requests UAC elevation automatically).
3. When it finishes, the PDF is written to `reports\vulnfinder_<hostname>_<timestamp>.pdf` next to the exe.

### Flags
```
VulnFinder.exe [-o path.pdf] [--no-pdf] [--quiet]
```

### Exit codes
- `0` — no criticals / highs
- `1` — one or more HIGH failures
- `2` — one or more CRITICAL failures

## What it checks

| Category | Examples |
|---|---|
| **System** | OS version, Secure Boot, TPM state, Credential Guard, Windows 10 EOL |
| **Firewall** | Profile enabled state, default inbound action, enabled allow-rules |
| **Defender / AV** | Real-time, tamper protection, signature age, ASR rules, Controlled Folder Access |
| **Accounts** | Admin group members, Guest enabled, built-in Administrator, PasswordRequired=False, autologon, UAC, LSA protection, LM hashes |
| **Password & Lockout** | Min length, complexity, history, lockout threshold, audit subcategory coverage |
| **BitLocker** | OS volume protection, encryption cipher, key protectors |
| **Updates** | Most recent hotfix age, WU services, NoAutoUpdate policy |
| **Network** | Listening TCP sockets, risky ports (23, 445, 3389 etc.), SMBv1, SMB signing, RDP / NLA, weak SSL/TLS |
| **Shares** | Share list, Everyone ACLs, null session access |
| **Services** | Risky services (Telnet, RemoteRegistry, WebClient...), execution policy, script-block logging, unquoted service paths |

Findings are classified `CRITICAL / HIGH / MEDIUM / LOW / INFO` and each carries an evidence snippet and a remediation command.

## Building from source

```powershell
pip install -r requirements.txt
python vulnfinder.py          # run directly
build.bat                      # produce dist\VulnFinder.exe
```

Requires Python 3.11+ on Windows.

## Notes

- The exe is unsigned, so SmartScreen may warn on first run. Click *More info → Run anyway*.
- Some endpoint protection products flag PyInstaller bootloaders. Whitelist the binary or build locally if that happens.
- Most checks need administrator privileges — running unelevated produces a partial report.
