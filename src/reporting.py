from .assessor import metrics


def render(findings) -> str:
    m=metrics(findings)
    lines=["# Delegation Security Assessment","","## Executive summary",f"- Findings: {m['total']}",f"- Critical: {m['critical']}",f"- High: {m['high']}",f"- Highest risk score: {m['max_score']}/100","","## Prioritized findings","","| ID | Principal | Finding | Score | Severity | ATT&CK |","|---|---|---|---:|---|---|"]
    for f in findings:
        lines.append(f"| {f.finding_id} | {f.principal} | {f.title} | {f.score} | {f.severity} | {', '.join(f.attack)} |")
    lines += ["","## Detail"]
    for f in findings:
        lines += ["",f"### {f.finding_id} - {f.title}",f"**Principal:** {f.principal}  ",f"**Risk:** {f.severity} ({f.score}/100)  ",f"**Rationale:** {', '.join(f.rationale) or 'base control risk'}  ",f"**Remediation:** {f.remediation}  ","**Validation:** re-export delegation configuration, confirm intended target scope, verify accountable ownership, and validate post-change authentication behavior."]
    lines += ["","## Interpretation","ATT&CK references provide defensive threat context only and do not indicate observed compromise or technique execution."]
    return "\n".join(lines)+"\n"
