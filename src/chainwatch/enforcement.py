from .types import PolicyResult, Decision
from .redaction import redact_auto, rewrite_output_text

class EnforcementError(Exception):
    pass

def enforce(result: PolicyResult, data: object) -> object:
    if result.decision == Decision.DENY:
        raise EnforcementError(result.reason)

    if result.decision == Decision.ALLOW:
        return data

    if result.decision == Decision.ALLOW_WITH_REDACTION:
        # basic structured redaction
        extra = None
        if result.redactions and "extra_keys" in result.redactions:
            extra = result.redactions["extra_keys"]
        return redact_auto(data, extra_keys=extra)

    if result.decision == Decision.REQUIRE_APPROVAL:
        raise EnforcementError(f"Approval required: {result.approval_key} ({result.reason})")

    if result.decision == Decision.REWRITE_OUTPUT:
        if isinstance(data, str):
            patterns = None
            if result.redactions and "patterns" in result.redactions:
                patterns = result.redactions["patterns"]
            return rewrite_output_text(data, patterns=patterns)
        return result.output_rewrite or ""

    return data
