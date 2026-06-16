"""Compliance framework mappings.

Each security check maps to one or more controls in every supported framework.
This is what lets the results page answer "which standards does this device
meet?" instead of only pass/fail. The mappings are kept as plain data (not
logic) so adding a framework or refining a control reference is a small edit
here and never touches the scanners.
"""

# Full display names, keyed by the short key used everywhere else. The order
# here is the order the framework tabs appear in on the results page.
FRAMEWORKS = {
    "cis": "CIS Microsoft Windows Benchmark",
    "nist_800_53": "NIST SP 800-53 Rev. 5",
    "iso_27001": "ISO/IEC 27001:2022 Annex A",
    "pci_dss": "PCI DSS v4.0",
}

# check_id -> framework key -> list of the controls that check provides evidence
# for. A passing check means the device meets those controls; a failing check
# means it does not; an errored check means they couldn't be assessed.
CONTROL_MAP = {
    "firewall_status": {
        "cis": [{"id": "9.1 – 9.3", "title": "Windows Firewall (Domain/Private/Public) state set to On"}],
        "nist_800_53": [{"id": "SC-7", "title": "Boundary Protection"}],
        "iso_27001": [{"id": "A.8.20", "title": "Networks security"}],
        "pci_dss": [{"id": "Requirement 1", "title": "Install and maintain network security controls"}],
    },
    "disk_encryption": {
        "cis": [{"id": "18.10.9", "title": "BitLocker Drive Encryption configured"}],
        "nist_800_53": [{"id": "SC-28", "title": "Protection of Information at Rest"}],
        "iso_27001": [{"id": "A.8.24", "title": "Use of cryptography"}],
        "pci_dss": [{"id": "Requirement 3", "title": "Protect stored account data"}],
    },
    "password_policy": {
        "cis": [{"id": "1.1.1 – 1.1.6", "title": "Account and Password Policy settings"}],
        "nist_800_53": [{"id": "IA-5", "title": "Authenticator Management"}],
        "iso_27001": [{"id": "A.5.17", "title": "Authentication information"}],
        "pci_dss": [{"id": "Requirement 8", "title": "Identify users and authenticate access"}],
    },
    "virtualization_security": {
        "cis": [{"id": "18.9.x", "title": "Device Guard / Virtualization Based Security"}],
        "nist_800_53": [{"id": "SI-7", "title": "Software, Firmware, and Information Integrity"}],
        "iso_27001": [{"id": "A.8.7", "title": "Protection against malware"}],
        "pci_dss": [{"id": "Requirement 5", "title": "Protect systems and networks from malicious software"}],
    },
}


def enrich(check: dict) -> dict:
    """Attach this check's compliance mapping in place, then return it.

    Unmapped checks get an empty mapping rather than raising, so a brand-new
    scanner still renders (just without framework references) until it's added
    to CONTROL_MAP above.
    """
    check["compliance"] = CONTROL_MAP.get(check["id"], {})
    return check
