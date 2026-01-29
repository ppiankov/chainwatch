# Output / filesystem interception

## Where interception happens
At the final output stage: file writes, clipboard access, or user-visible responses.

## What Chainwatch sees
- Final output content
- Destination (file, clipboard, stdout)
- Output size and format

## What Chainwatch can control
- Redact or rewrite outputs
- Block exfiltration
- Apply watermarks or summaries

## What Chainwatch cannot control
- Data access earlier in execution
- Intermediate tool usage
- Over-collection upstream

## When this makes sense
- Last-resort protection
- Demonstrations
- Supplementary control layer

## Notes
This is not sufficient alone.
It complements upstream interception strategies.
