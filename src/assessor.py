import json
from .models import DelegationRecord, Finding, VALID_TYPES, VALID_CRITICALITY, finding_id, severity

REQUIRED = {"principal","delegation_type","enabled","privileged","protocol_transition","interactive_logon","managed_identity","target_count","rbcd_writer_count","criticality","owner","review_age_days"}


def load_records(path: str) -> list[DelegationRecord]:
    data = json.load(open(path, encoding="utf-8"))
    if not isinstance(data, list): raise ValueError("evidence must be a JSON list")
    seen=set(); records=[]
    for item in data:
        if not isinstance(item, dict) or REQUIRED - set(item): raise ValueError("record missing required fields")
        if item["principal"] in seen: raise ValueError("duplicate principal")
        seen.add(item["principal"])
        if item["delegation_type"] not in VALID_TYPES: raise ValueError("unsupported delegation_type")
        if item["criticality"] not in VALID_CRITICALITY: raise ValueError("unsupported criticality")
        for key in ("enabled","privileged","protocol_transition","interactive_logon","managed_identity"):
            if type(item[key]) is not bool: raise ValueError(f"{key} must be boolean")
        for key in ("target_count","rbcd_writer_count","review_age_days"):
            if type(item[key]) is not int or item[key] < 0: raise ValueError(f"{key} must be non-negative integer")
        if not str(item["principal"]).strip() or not str(item["owner"]).strip(): raise ValueError("principal and owner are required")
        records.append(DelegationRecord(**item))
    return records


def _score(base: int, r: DelegationRecord) -> tuple[int, tuple[str,...]]:
    score=base; why=[]
    if r.privileged: score += 15; why.append("privileged principal")
    if r.interactive_logon: score += 8; why.append("interactive logon enabled")
    if not r.managed_identity: score += 8; why.append("identity is not managed")
    if r.target_count > 10: score += 8; why.append("broad delegation target scope")
    if r.rbcd_writer_count > 3: score += 10; why.append("multiple RBCD writers")
    if r.criticality == "critical": score += 12; why.append("critical business context")
    elif r.criticality == "high": score += 7; why.append("high business context")
    if r.review_age_days > 365: score += 7; why.append("governance review older than one year")
    if not r.enabled: score -= 25; why.append("principal disabled")
    return max(0,min(100,score)), tuple(why)


def assess(records: list[DelegationRecord]) -> list[Finding]:
    findings=[]
    for r in records:
        candidates=[]
        if r.delegation_type == "unconstrained": candidates.append(("Unconstrained delegation enabled",72,("T1550","T1558"),"Remove unconstrained delegation; use narrowly scoped constrained delegation only where justified."))
        if r.delegation_type == "constrained" and r.protocol_transition: candidates.append(("Protocol transition enabled",55,("T1550","T1078"),"Validate S4U requirement, restrict service targets, and document business justification."))
        if r.delegation_type == "rbcd" and r.rbcd_writer_count > 1: candidates.append(("RBCD writer scope requires review",58,("T1098","T1078"),"Restrict principals permitted to configure resource-based constrained delegation."))
        if r.delegation_type != "none" and r.privileged: candidates.append(("Privileged identity has delegation rights",70,("T1078","T1558"),"Separate privileged administration from delegated service identities and remove unnecessary privilege."))
        for title,base,attack,remediation in candidates:
            score,why=_score(base,r)
            findings.append(Finding(finding_id(r.principal,title),r.principal,title,score,severity(score),why,attack,remediation))
    return sorted(findings,key=lambda f:(-f.score,f.principal,f.title))


def metrics(findings: list[Finding]) -> dict:
    return {"total":len(findings),"critical":sum(f.severity=="Critical" for f in findings),"high":sum(f.severity=="High" for f in findings),"max_score":max((f.score for f in findings),default=0)}
