import json
from datetime import datetime, timezone
from pathlib import Path

from scanners import run_all

REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def compute_score(results) -> int:
    # Checks that errored (couldn't be verified) are excluded rather than
    # counted as failures, so an unsupported check doesn't unfairly tank the score.
    scored = [r for r in results if r.status in ("pass", "fail")]
    if not scored:
        return 0
    passed = sum(1 for r in scored if r.status == "pass")
    return round((passed / len(scored)) * 100)


def main():
    results = run_all()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "compliance_score": compute_score(results),
        "checks": [r.to_dict() for r in results],
    }

    REPORTS_DIR.mkdir(exist_ok=True)
    output_path = REPORTS_DIR / "scan_results.json"
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Compliance score: {report['compliance_score']}%")
    for result in results:
        print(f"  [{result.status.upper():5}] {result.name}")
    print(f"\nFull report written to {output_path}")


if __name__ == "__main__":
    main()
