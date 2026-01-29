# Threat model (v0)

## Assets
- Sensitive datasets (PII, HR, salary, security logs, customer data)
- Agent credentials and tokens
- Outputs produced for the user

## Adversaries / failures
- Prompt injection leading agent to exfiltrate
- Over-collection caused by agent autonomy
- Legitimate user receiving unsafe output
- Compromised agent or tool connector

## Non-goals (v0)
- Preventing all prompt injection
- Detecting novel malware
- Replacing IAM/PAM/DLP
