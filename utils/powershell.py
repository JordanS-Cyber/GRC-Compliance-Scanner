import json
import os
import subprocess


class PowerShellError(Exception):
    pass


def system_executable(*parts: str) -> str:
    """Resolve a Windows system executable to its absolute System32 path.

    Invoking system tools (powershell.exe, net.exe, ...) by full path rather than
    a bare name prevents a malicious binary planted in the current working
    directory or earlier on PATH from being executed in their place -- a real
    risk for a tool that may be launched from an attacker-influenced directory.
    Falls back to the bare name (normal PATH lookup) only when the expected
    absolute path isn't present, so unusual environments still work.
    """
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    resolved = os.path.join(system_root, "System32", *parts)
    return resolved if os.path.isfile(resolved) else parts[-1]


POWERSHELL = system_executable("WindowsPowerShell", "v1.0", "powershell.exe")


def run_command(command: str, timeout: int = 30) -> str:
    """Run a PowerShell command and return its raw stdout as text.

    -NoProfile / -NonInteractive keep this fast and prevent a user's profile script
    (or a prompt) from blocking an unattended scan. -ExecutionPolicy Bypass only
    affects this one-off invocation, not the system-wide policy.
    """
    try:
        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        # Covers timeouts (TimeoutExpired) and a missing/unrunnable interpreter,
        # so one stuck or unavailable check can't crash the whole scan -- the
        # scanners already treat PowerShellError as a graceful "couldn't run".
        raise PowerShellError(str(exc) or "PowerShell command failed to run")
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
