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

## Real-world agent vulnerabilities

A recent independent security audit of an open-source AI agent (Clawdbot / Moltbot)
identified numerous critical issues ranging from arbitrary code execution via `eval()`,
to lack of rate limiting, to unsafe extension loading. These findings demonstrate that
agent tooling can introduce severe systemic risks when capabilities are unrestricted:

- Arbitrary execution (`eval()`) enabling cookie theft and arbitrary actions  
- Lack of rate limiting leading to denial of service  
- Unsafe plugin loading with no cryptographic verification  

Cataloged attack scenarios include exfiltration of SSH keys, browser credentials,
API key leakage, lateral movement, and full chained compromise paths.  [oai_citation:1‡Habr](https://habr.com/ru/articles/989764/)

Recent independent security audits of open-source AI agents have demonstrated that agents
can legally invoke highly privileged operations — including arbitrary code execution,
filesystem access, browser automation, and network exfiltration — without violating any
single traditional security control. These audits document numerous realistic attack paths
where agents are compromised or misused due to the absence of chain-aware enforcement,
rather than misconfigured IAM or network defenses. This threat model assumes such failures
are plausible and focuses on reducing blast radius by enforcing policy at runtime across
the full execution chain.
