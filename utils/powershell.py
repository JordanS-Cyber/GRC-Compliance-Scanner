import json
import subprocess


class PowerShellError(Exception):
    pass


def run_command(command: str, timeout: int = 30) -> str:
    """Run a PowerShell command and return its raw stdout as text.

    -NoProfile / -NonInteractive keep this fast and prevent a user's profile script
    (or a prompt) from blocking an unattended scan. -ExecutionPolicy Bypass only
    affects this one-off invocation, not the system-wide policy.
    """
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise PowerShellError(result.stderr.strip() or "PowerShell command failed")
    return result.stdout.strip()


def run_command_json(command: str, timeout: int = 30):
    """Run a PowerShell command whose output ends in ConvertTo-Json and parse it.

    Asking PowerShell to emit JSON (rather than scraping its formatted text tables)
    is what keeps each scanner's parsing logic simple and resilient to column-width
    quirks in PowerShell's default output.
    """
    output = run_command(command, timeout=timeout)
    if not output:
        # Some cmdlets print nothing when the queried object doesn't exist
        # (e.g. no BitLocker volume) rather than raising an error.
        return None
    return json.loads(output)
