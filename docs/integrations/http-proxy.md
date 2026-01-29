# HTTP / API proxy integration

## Where interception happens
At the network boundary via a local or sidecar HTTP proxy.

## What Chainwatch sees
- Destination host and path
- Request/response size
- Headers and payloads (optionally)
- Timing and frequency

## What Chainwatch can control
- Block outbound requests
- Rate-limit or throttle
- Rewrite responses
- Detect obvious exfiltration

## What Chainwatch cannot control
- Fine-grained field-level semantics
- Non-HTTP actions
- Clear attribution to agent intent

## When this makes sense
- Closed agent runtimes
- External SaaS/API access
- Model-agnostic enforcement

## Notes
Less semantic than tool wrappers, but works without agent cooperation.
