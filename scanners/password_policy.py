import subprocess

from scanners.base import CheckResult
from utils.parsing import parse_colon_table
from utils.powershell import system_executable

CHECK_ID = "password_policy"
CHECK_NAME = "Local Password Policy"
CATEGORY = "Identity & Access Management"

MIN_RECOMMENDED_LENGTH = 8


def _run_net_accounts() -> str:
    # `net accounts` reads the local security policy and works without
    # elevation, unlike `secedit`, so it's used here over a PowerShell module.
    result = subprocess.run(
        [system_executable("net.exe"), "accounts"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "net accounts failed")
    return result.stdout


def run() -> CheckResult:
    try:
        policy = parse_colon_table(_run_net_accounts())
    except Exception as exc:
        return CheckResult(
            id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
            status="error", risk_level="unknown", value=str(exc),
            business_risk="Unable to verify the local password policy.",
            remediation="Run this scan on a Windows host where the 'net accounts' command is available.",
        )

    min_length_raw = policy.get("Minimum password length", "0")
    try:
        min_length = int(min_length_raw)
    except ValueError:
        # Some locales/policies report this as a non-numeric value;
        # treat anything unparsable as "no minimum enforced".
        min_length = 0

    max_age_raw = policy.get("Maximum password age (days)", "Unlimited")

    issues = []
    if min_length < MIN_RECOMMENDED_LENGTH:
        issues.append(f"minimum password length is only {min_length} characters")
    if max_age_raw.lower() in ("unlimited", "never"):
        issues.append("passwords never expire")

    if issues:
        status, risk_level = "fail", "medium"
        business_risk = (
            "Weak password policy detected (" + "; ".join(issues) + "). "
            "Weak or non-expiring passwords increase the likelihood of account "
            "compromise through credential stuffing or brute-force attacks."
        )
        remediation = (
            "Enforce a minimum password length of at least 8-14 characters and set a "
            "reasonable maximum password age, e.g.: net accounts /minpwlen:14 /maxpwage:90"
        )
    else:
        status, risk_level = "pass", "low"
        business_risk = "Local password policy meets minimum length and expiration recommendations."
        remediation = "No action required."

    return CheckResult(
        id=CHECK_ID, name=CHECK_NAME, category=CATEGORY,
        status=status, risk_level=risk_level,
        value=policy, business_risk=business_risk, remediation=remediation,
    )
