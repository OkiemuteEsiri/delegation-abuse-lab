REQUIRED = {"change_reference","owner","delegation_corrected","privilege_reviewed","post_change_export","authentication_validated"}


def validate_closure(evidence: dict) -> tuple[str,list[str]]:
    if not isinstance(evidence,dict): return "invalid_closure",["evidence must be an object"]
    missing=sorted(REQUIRED-set(evidence))
    if missing: return "needs_evidence",missing
    if not str(evidence["change_reference"]).strip() or not str(evidence["owner"]).strip(): return "needs_evidence",["change_reference","owner"]
    controls=["delegation_corrected","privilege_reviewed","post_change_export","authentication_validated"]
    bad=[k for k in controls if evidence[k] is not True]
    if bad: return "invalid_closure",bad
    return "validated",[]
