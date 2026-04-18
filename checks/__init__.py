from .runner import run_command, run_powershell, Finding, Severity, Status
from . import firewall, defender, accounts, network, updates, policies, encryption, services, system, shares

ALL_MODULES = [
    ("System Information", system),
    ("Firewall", firewall),
    ("Windows Defender & Antivirus", defender),
    ("User Accounts & Authentication", accounts),
    ("Password & Lockout Policy", policies),
    ("Disk Encryption", encryption),
    ("Windows Update", updates),
    ("Network & Open Ports", network),
    ("Network Shares", shares),
    ("Services & Attack Surface", services),
]


def run_all():
    results = []
    for category, module in ALL_MODULES:
        findings = module.run()
        results.append((category, findings))
    return results
