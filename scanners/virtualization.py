from scanners.base import CheckResult
from utils.powershell import PowerShellError, run_command_json

CHECK_ID = "virtualization_security"
CHECK_NAME = "Virtualization-Based Security (Hyper-V/VBS)"
CATEGORY = "Endpoint Hardening"


def run() -> CheckResult:
    # Get-ComputerInfo -Property limits the query to just these two fields
    # instead of pulling the full (slow) system info object.
    command = (
        "Get-ComputerInfo -Property "
        "'HyperVRequirementVirtualizationFirmwareEnabled',"
        "'DeviceGuardVirtualizationBasedSecurityStatus' | ConvertTo-Json"
    )
    try:
        info = run_command_json(command)
    except (PowerShellError, ValueError) as exc:
        return CheckResult(
            id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
            status="error", risk_level="unknown", value=str(exc),
            business_risk="Unable to verify virtualization-based security status.",
            remediation="Run this scan on Windows 10/11 with the ComputerInfo cmdlet available.",
        )

    info = info or {}
    firmware_enabled = bool(info.get("HyperVRequirementVirtualizationFirmwareEnabled"))
    vbs_status = str(info.get("DeviceGuardVirtualizationBasedSecurityStatus", "")).strip()
    # "Running" is the only value that means VBS is actually active; other
    # states ("Not enabled", "Not running") all collapse to a fail.
    vbs_running = vbs_status.lower() == "running"

    if firmware_enabled and vbs_running:
        status, risk_level = "pass", "low"
        business_risk = (
            "Virtualization-based security is active, helping isolate sensitive "
            "OS processes from malware even if the kernel is compromised."
        )
        remediation = "No action required."
    else:
        status, risk_level = "fail", "medium"
        business_risk = (
            "Virtualization (Hyper-V) and/or Virtualization-Based Security (VBS) is not "
            "fully enabled. Without VBS, the system has fewer protections against "
            "credential theft and kernel-level malware."
        )
        remediation = (
            "Enable virtualization in the system firmware (BIOS/UEFI) and turn on Core "
            "Isolation / Memory Integrity via Windows Security > Device Security, or "
            "via Group Policy: Turn On Virtualization Based Security."
        )

    return CheckResult(
        id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
        status=status, risk_level=risk_level,
        value=info, business_risk=business_risk, remediation=remediation,
    )
