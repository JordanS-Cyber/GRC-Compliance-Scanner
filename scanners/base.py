from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CheckResult:
    """Standard shape every scanner must return.

    Keeping this schema identical across scanners is what lets main.py and the
    future dashboard render any check (current or new) without special-casing it.
    """

    id: str
    name: str
    category: str
    status: str  # "pass", "fail", "error" -- "error" means the check itself couldn't run
    risk_level: str  # "low", "medium", "high", "critical", "unknown"
    value: Any  # raw data behind the result, kept for the dashboard's detail view
    business_risk: str  # plain-English translation of the technical finding
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)
