import os

from .runner import run_command, run_powershell, Finding, Severity, Status
from . import (
    firewall, defender, accounts, network, updates, policies, encryption,
    services, system, shares, credentials, protocols, mitigations,
    event_logging, software, feeds,
)


ALL_MODULES = [
    ("System Information",            system),
    ("Firewall",                      firewall),
    ("Windows Defender & Antivirus",  defender),
    ("User Accounts & Authentication", accounts),
    ("Credential Protection",         credentials),
    ("Password & Lockout Policy",     policies),
    ("Disk Encryption",               encryption),
    ("Windows Update",                updates),
    ("Network & Open Ports",          network),
    ("Name Resolution & Legacy Protocols", protocols),
    ("Network Shares",                shares),
    ("Services & Attack Surface",     services),
    ("Installed Software & Tasks",    software),
    ("Exploit Mitigations",           mitigations),
    ("Logging & Visibility",          event_logging),
    ("Live Vulnerability Advisories", feeds),
]


def run_all():
    results = []
    for category, module in ALL_MODULES:
        if module is feeds:
            findings = module.run(offline=bool(os.environ.get("BASTION_OFFLINE")))
        else:
            findings = module.run()
        results.append((category, findings))
    return results
