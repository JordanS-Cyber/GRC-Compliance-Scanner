# GRC Compliance Scanner

A lightweight, local security and compliance scanner for **Windows**. It checks
your device against common security baselines, scores it, maps every finding to
real compliance frameworks (CIS, NIST 800-53, ISO 27001, PCI DSS), and produces
an interactive HTML report that explains *why* each check passed or failed and
*what to do about it*.

Everything runs locally on your machine. No data leaves your device.

## What it checks

| Check | Category | Looks at |
|-------|----------|----------|
| Windows Firewall Status | Network Security | Domain / Private / Public profiles are enabled |
| Disk Encryption (BitLocker) | Data Protection | System drive is encrypted |
| Local Password Policy | Identity & Access | Minimum length and password expiration |
| Virtualization-Based Security | Endpoint Hardening | Hyper-V firmware + VBS / Memory Integrity |

Each result is mapped to the matching control in **CIS Microsoft Windows
Benchmark**, **NIST SP 800-53 Rev. 5**, **ISO/IEC 27001:2022**, and **PCI DSS v4.0**.

## Requirements

- **Windows 10 or 11** (the scanner uses PowerShell and `net accounts`; it will
  not work on macOS or Linux)
- **Python 3.8 or newer** — check with `python --version`
- No third-party packages — it uses only the Python standard library
- **Administrator privileges recommended.** Some checks (notably BitLocker) need
  an elevated terminal to read their status; without it they report
  "Not assessed" rather than a pass/fail.

## Download and run

### Option A — clone with Git

```powershell
git clone https://github.com/JordanS-Cyber/GRC-Compliance-Scanner.git
cd GRC-Compliance-Scanner
python main.py
```

### Option B — download the ZIP (no Git needed)

1. Go to <https://github.com/JordanS-Cyber/GRC-Compliance-Scanner>
2. Click the green **Code** button → **Download ZIP**
3. Extract it, then open PowerShell in the extracted folder and run:

```powershell
python main.py
```

> **Tip:** to capture the checks that require elevation (like BitLocker), run
> PowerShell **as Administrator** before `python main.py`.

## Viewing your results

After the scan finishes you'll see a summary in the terminal, for example:

```
Compliance score: 33%
  [PASS ] Windows Firewall Status
  [ERROR] Disk Encryption (BitLocker)
  [FAIL ] Local Password Policy
  [FAIL ] Virtualization-Based Security (Hyper-V/VBS)

JSON report:  ...\reports\scan_results.json
HTML report:  ...\reports\results.html
```

Two files are written to the `reports/` folder:

- **`results.html`** — open this in any web browser. It's a self-contained page
  (no internet connection needed). Use the **Summary** tab to see every check
  with its reason and fix, or click a **framework tab** (e.g. *PCI DSS*) to see
  how your device measures up to that specific standard, control by control.
- **`scan_results.json`** — the same data in machine-readable form, handy for
  feeding into other tools.

To open the report from PowerShell:

```powershell
start reports\results.html
```

## How the score works

The compliance score is the percentage of **assessable** checks that passed.
Checks that couldn't run on your device (shown as "Not assessed" / `error`) are
excluded from the score so an unsupported feature doesn't unfairly drag it down.

## Privacy

The generated reports contain details about your local configuration and are
**not** committed to the repository (`reports/*.json` and `reports/*.html` are
git-ignored). Treat them as sensitive — they describe your device's security posture.

## Project layout

```
main.py              # entry point: runs the scan, writes JSON + HTML
scanners/            # one module per check (firewall, bitlocker, etc.)
utils/               # PowerShell + text parsing helpers
compliance.py        # maps each check to CIS / NIST / ISO / PCI controls
dashboard/report.py  # builds the interactive HTML report
reports/             # generated output (git-ignored)
```
