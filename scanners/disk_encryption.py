from scanners.base import CheckResult
from utils.powershell import PowerShellError, run_command_json

CHECK_ID = "disk_encryption"
CHECK_NAME = "Disk Encryption (BitLocker)"
CATEGORY = "Data Protection"


def run() -> CheckResult:
    # $env:SystemDrive (not a hardcoded "C:") so this still works if Windows
    # is installed on a different drive letter.
    command = (
        "Get-BitLockerVolume -MountPoint $env:SystemDrive | "
        "Select-Object MountPoint, VolumeStatus, ProtectionStatus | ConvertTo-Json"
    )
    try:
        volume = run_command_json(command)
    except (PowerShellError, ValueError) as exc:
        # Get-BitLockerVolume commonly fails on Windows Home (no BitLocker)
        # or without elevation -- treat as "couldn't verify", not "fail".
        return CheckResult(
            id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
            status="error", risk_level="unknown", value=str(exc),
            business_risk=(
                "Unable to verify BitLocker status. This often requires administrator "
                "privileges, or BitLocker may not be available on this edition of Windows."
            ),
            remediation="Rerun the scan as an administrator on a Windows edition that supports BitLocker (Pro/Enterprise/Education).",
        )

    if not volume:
        # Cmdlet ran fine but returned nothing -- no BitLocker-capable volume exists.
        return CheckResult(
            id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
            status="error", risk_level="unknown", value=None,
            business_risk="No BitLocker-capable volume was found for the system drive.",
            remediation="Verify BitLocker is supported and available on this device.",
        )

    # ProtectionStatus is an enum that serializes to JSON as either its
    # numeric value (1) or name ("On") depending on PowerShell version.
    protection_status = str(volume.get("ProtectionStatus", "")).strip()
    is_protected = protection_status in ("1", "On")

    if is_protected:
        status, risk_level = "pass", "low"
        business_risk = "The system drive is encrypted, protecting data at rest in the event of physical theft or loss."
        remediation = "No action required."
    else:
        status, risk_level = "fail", "high"
        business_risk = (
            "BitLocker is not enabled on the system drive. If the device is lost or "
            "stolen, sensitive business data could be read directly off the disk, "
            "creating significant data breach and compliance exposure."
        )
        remediation = (
            "Enable BitLocker on the system drive via Control Panel > BitLocker Drive "
            "Encryption, or run as administrator: Enable-BitLocker -MountPoint $env:SystemDrive"
        )

    return CheckResult(
        id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
        status=status, risk_level=risk_level,
        value=volume, business_risk=business_risk, remediation=remediation,
    )
