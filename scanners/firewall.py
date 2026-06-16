from scanners.base import CheckResult
from utils.powershell import PowerShellError, run_command_json

CHECK_ID = "firewall_status"
CHECK_NAME = "Windows Firewall Status"
CATEGORY = "Network Security"


def _is_enabled(value) -> bool:
    """Interpret a firewall profile's Enabled property as a boolean.

    Get-NetFirewallProfile exposes Enabled as the GpoBoolean enum, which can
    arrive from ConvertTo-Json as an int (1 = on), a bool, or a string depending
    on the PowerShell/OS version. Only values we positively recognise as "on"
    count as enabled; anything else is treated as disabled so an unexpected
    representation fails safe (flagged as a gap) instead of silently masking a
    switched-off firewall.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "enabled")
    return False


def run() -> CheckResult:
    # -All covers Domain/Private/Public in one call; a single disabled profile
    # is enough to leave the host exposed on whichever network it's using.
    command = "Get-NetFirewallProfile -All | Select-Object Name, Enabled | ConvertTo-Json"
    try:
        profiles = run_command_json(command)
    except (PowerShellError, ValueError) as exc:
        return CheckResult(
            id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
            status="error", risk_level="unknown", value=str(exc),
            business_risk="Unable to verify firewall status.",
            remediation="Ensure the Windows Firewall service is running and rerun the scan.",
        )

    if profiles is None:
        profiles = []
    # ConvertTo-Json collapses a single-item array to a bare object, not a list.
    if isinstance(profiles, dict):
        profiles = [profiles]

    disabled = [p.get("Name", "Unknown") for p in profiles if not _is_enabled(p.get("Enabled"))]

    if not profiles:
        status, risk_level = "error", "unknown"
    elif disabled:
        status, risk_level = "fail", "high"
    else:
        status, risk_level = "pass", "low"

    if disabled:
        business_risk = (
            f"The following firewall profile(s) are disabled: {', '.join(disabled)}. "
            "An inactive firewall profile leaves the network exposed to unauthorized "
            "inbound connections and increases the risk of malware and unauthorized access."
        )
        remediation = (
            "Enable the Windows Firewall for all network profiles "
            "(Domain, Private, and Public) via Control Panel > Windows Defender Firewall, "
            "or run: Set-NetFirewallProfile -All -Enabled True"
        )
    elif status == "pass":
        business_risk = "All firewall profiles are active, reducing exposure to unauthorized network traffic."
        remediation = "No action required."
    else:
        business_risk = "No firewall profile data could be retrieved."
        remediation = "Verify the Windows Firewall service is running and rerun the scan."

    return CheckResult(
        id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
        status=status, risk_level=risk_level,
        value=profiles, business_risk=business_risk, remediation=remediation,
    )
