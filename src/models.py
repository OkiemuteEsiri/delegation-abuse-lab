from dataclasses import dataclass
from hashlib import sha256

VALID_TYPES = {"none", "unconstrained", "constrained", "rbcd"}
VALID_CRITICALITY = {"low", "medium", "high", "critical"}

@dataclass(frozen=True)
class DelegationRecord:
    principal: str
    delegation_type: str
    enabled: bool
    privileged: bool
    protocol_transition: bool
    interactive_logon: bool
    managed_identity: bool
    target_count: int
    rbcd_writer_count: int
    criticality: str
    owner: str
    review_age_days: int

@dataclass(frozen=True)
class Finding:
    finding_id: str
    principal: str
    title: str
    score: int
    severity: str
    rationale: tuple[str, ...]
    attack: tuple[str, ...]
    remediation: str


def finding_id(principal: str, title: str) -> str:
    return "ADDEL-" + sha256(f"{principal}|{title}".encode()).hexdigest()[:12].upper()


def severity(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 70: return "High"
    if score >= 40: return "Medium"
    return "Low"
