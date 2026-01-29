# Security Policy

## Status

Chainwatch is an **experimental prototype** (v0.1.0). It is not intended for production use.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :warning: Prototype only |

## Known Security Limitations

### Architecture
- **No authentication**: FileGuard does not validate caller identity
- **No authorization persistence**: Approval decisions are not stored
- **In-memory only**: No audit log persistence (events lost on restart)
- **Single process**: No multi-tenant isolation

### File Wrapper
- **Monkey-patching scope**: Only intercepts Python `open()` and `pathlib.Path` methods
- **Bypass potential**: C extensions, subprocess calls, and direct syscalls are not intercepted
- **Path-based classification**: Sensitive files with obfuscated names may not be detected
- **No write monitoring**: Only read operations are enforced

### Policy Engine
- **Hardcoded rules**: Policy logic is in source code (no runtime configuration validation)
- **No rate limiting**: Repeated access attempts are not throttled
- **No anomaly detection**: Only deterministic rule matching

## Responsible Disclosure

If you discover a security issue in Chainwatch:

1. **DO NOT** open a public GitHub issue
2. Email: ppiankov@users.noreply.github.com with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested mitigation (if any)

**Response time:** Best-effort for prototype stage. No SLA guarantees.

## Security Roadmap

### v0.2.0 (Planned)
- Event persistence (Postgres with audit logging)
- Policy configuration validation
- HTTP proxy mode with TLS inspection
- Approval workflow with audit trail

### v1.0.0 (Future)
- Multi-tenant isolation
- Rate limiting and circuit breakers
- Anomaly detection (statistical baselines)
- OpenTelemetry security event export

## Out of Scope

Chainwatch is **not**:
- A replacement for IAM/RBAC systems
- A prompt injection firewall
- A data loss prevention (DLP) tool
- A malware scanner

It is designed to work **alongside** existing security controls, not replace them.

## Best Practices for Testing

If you are evaluating Chainwatch:

1. **Use isolated environments**: Run demos in VMs or containers
2. **Test data only**: Use synthetic corporate data (see `examples/test_data/`)
3. **No production credentials**: Never test with real API keys or passwords
4. **Monitor resource usage**: File wrapper may impact I/O-heavy workloads
5. **Review traces**: Inspect `guard.get_trace_summary()` for unexpected data leakage

## Questions?

For security-related questions that are not vulnerabilities, open a GitHub Discussion or email the maintainer.

This is a research prototype.
