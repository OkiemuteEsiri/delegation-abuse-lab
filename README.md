# Active Directory Delegation Security Lab

Defensive, offline assessment of synthetic Active Directory delegation configuration. The project models delegation-risk review without querying a domain controller, requesting Kerberos tickets, collecting credentials, or performing exploitation.

## Problem statement
Kerberos delegation can create high-impact identity paths when unconstrained delegation, protocol transition, resource-based constrained delegation, privileged principals, or weak ownership controls are misconfigured. This lab turns exported or synthetic identity metadata into deterministic findings that security teams can prioritize and validate.

## Architecture
`JSON evidence -> validator -> delegation assessor -> risk engine -> prioritized findings -> Markdown report -> remediation validation`

## Controls assessed
- Unconstrained delegation on enabled principals
- Constrained delegation with protocol transition
- Resource-based constrained delegation with broad or privileged writers
- Delegation granted to privileged service identities
- Interactive logon enabled for delegated service accounts
- Missing managed service-account controls
- Excessive delegation target scope
- Stale review dates and ownership gaps

## Usage
```bash
python -m src.cli data/synthetic_delegation.json --output reports/generated-assessment.md
```

## Testing
```bash
python -m unittest discover -s tests -v
```

## Risk model
Each finding starts from a control-specific base risk and adds documented modifiers for privilege, account enablement, interactive logon, unmanaged service identity, broad delegation scope, criticality, and stale governance. Scores are capped at 100 and mapped to Critical/High/Medium/Low. Disabled principals receive a reduction but are retained for governance visibility.

## MITRE ATT&CK context
Mappings are used only as threat-model context:
- T1550 - Use Alternate Authentication Material
- T1558 - Steal or Forge Kerberos Tickets
- T1078 - Valid Accounts
- T1098 - Account Manipulation

These mappings do not assert that any technique was executed.

## Safety scope
This repository is intentionally defensive. It contains no ticket requests, password cracking, LDAP enumeration, credential collection, relay logic, exploit code, or production targeting. All datasets are fictional.

## Repository structure
```text
.github/workflows/security-quality.yml
data/synthetic_delegation.json
docs/architecture-methodology.md
reports/example-assessment.md
src/models.py
src/assessor.py
src/reporting.py
src/remediation.py
src/cli.py
tests/test_delegation_assessor.py
```

## Remediation workflow
1. Assign accountable owner and change reference.
2. Remove unsafe delegation or constrain scope.
3. Move eligible service identities to managed accounts.
4. Remove unnecessary interactive logon and privileged memberships.
5. Re-export configuration evidence after change.
6. Run the assessor again and attach validation evidence.
7. Close only when the control state and post-change authentication validation are both confirmed.

## Limitations
This is not a replacement for directory-native tooling, BloodHound, event telemetry, or a formal identity assessment. It does not establish exploitability, compromise, or actual ticket abuse. It evaluates supplied configuration evidence only.

## Skills demonstrated
Active Directory security engineering, Kerberos delegation governance, identity-risk modeling, Python, validation, deterministic analytics, remediation evidence design, ATT&CK mapping, technical reporting, unit testing, and CI/CD quality controls.

## Roadmap
- Graph-aware delegation target analysis
- Policy-as-code export for approved delegation patterns
- JSON/SARIF output
- Snapshot trend comparison
- Synthetic detection telemetry for delegation-related change events
