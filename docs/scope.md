# Scope and supported agent classes

Chainwatch is designed to operate across multiple agent ecosystems,
including proprietary SaaS agents and local open-source runtimes.

Rather than targeting specific vendors, Chainwatch focuses on
common agent execution patterns.

## Supported agent classes

| Agent class     | Examples                                      | Primary insertion        |
|-----------------|-----------------------------------------------|--------------------------|
| Tool-driven     | Claude Code, OpenCode, Codex, Clawdbot        | Tool wrapper             |
| SaaS copilots   | ChatGPT Atlas, Claude Co-Worker, Perplexity   | Network / output         |
| Local agents    | Ollama                                        | Tool + filesystem        |
| Hybrid          | Mixed                                         | Combination of applicable strategies |

Examples are illustrative only and do not imply official support,
endorsement, or deep integration with any specific vendor or product.

Chainwatch makes no assumptions about agent internals and operates only at
boundaries that can be intercepted and enforced.
