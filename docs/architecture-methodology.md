# Architecture and methodology

## Objective
Provide a safe, repeatable way to review Active Directory delegation posture from supplied configuration evidence. The tool deliberately performs no directory discovery or Kerberos interaction.

## Trust boundaries
1. **Evidence boundary:** JSON is untrusted and validated before analysis.
2. **Analysis boundary:** scoring is deterministic and side-effect free.
3. **Reporting boundary:** reports contain synthetic/configuration findings only.
4. **Closure boundary:** remediation is not accepted without explicit post-change evidence.

## Methodology
The assessor classifies the supplied delegation model, evaluates unsafe combinations, applies contextual modifiers, maps defensive ATT&CK context, sorts findings by risk, and produces remediation guidance.

### Risk factors
Base control risk is modified by privilege, interactive logon, lack of managed identity, broad target scope, RBCD writer breadth, business criticality, stale review age, and disabled status. Scores are bounded to 0-100.

## Validation philosophy
A configuration change alone is not treated as closure. Validation should demonstrate the intended delegation state, reviewed privilege, a new evidence export, and successful authentication behavior after the change.

## ATT&CK context
T1550, T1558, T1078, and T1098 are included to connect identity-control weaknesses to common threat concepts. This is contextual mapping only.

## Limitations
The assessor does not model every Kerberos nuance, nested AD group path, ACL inheritance edge, forest trust, or certificate-service interaction. Results depend on evidence completeness and should be corroborated using approved enterprise tooling.
