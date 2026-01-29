# Decision Record 002: Path-Based File Classification

**Status:** Accepted
**Date:** 2026-01-29
**Deciders:** Core team
**Related:** docs/integrations/file-ops-wrapper.md

## Context

FileGuard needs to classify file sensitivity to make policy decisions. Two approaches considered:

1. **Path-based**: Pattern matching on file paths (e.g., "hr", "salary")
2. **Content-based**: Parse file contents to detect sensitive data

## Decision

Use path-based classification for v0.1.0 MVP.

## Rationale

### Why Path-Based

**Fast and deterministic:**
- No file I/O required before policy decision
- Sub-millisecond classification
- No parsing errors or format dependencies

**Good enough for MVP:**
- Most organizations have naming conventions (hr/, payroll/, etc.)
- False positives are acceptable (over-enforcement is safe)
- Proves enforcement semantics without complex classification

**Simple implementation:**
- ~20 lines of pattern matching
- Easy to test
- No external dependencies

**Transparent:**
- Users can predict classification by inspecting paths
- No "black box" ML model
- Failures are obvious (wrong path pattern)

### Why Not Content-Based (Yet)

**Complexity:**
- Requires parsing CSV, JSON, XML, plain text
- Format detection is error-prone
- PII detection needs sophisticated NLP or regex libraries

**Performance:**
- Must read file contents before policy decision
- Large files (>1GB) would slow enforcement
- I/O failures complicate enforcement path

**Ambiguity:**
- What if file contains both PII and non-sensitive data?
- How much content to scan? (first 100 rows? all rows?)
- Binary files hard to classify

## Expected Limitations

### False Positives (Over-Enforcement)
- `/finance/quarterly_report.csv` → classified as high (no "salary" but finance-related)
- `/personal_projects/code.py` → classified as high (contains "personal")

**Impact:** Acceptable. Over-enforcement is safer than under-enforcement.

### False Negatives (Under-Enforcement)
- `/data/compensation.csv` → classified as low (no "salary" or "payroll" keyword)
- `/exports/emp_data_20250129.csv` → classified as low (obfuscated naming)

**Impact:** Requires organizational naming conventions. Document in CONTRIBUTING.md.

## Evolution Path

### v0.2.0: Hybrid Approach
- Keep path-based as first pass (fast)
- Add optional content-based refinement (slower but accurate)
- User-defined classification rules in YAML config

```yaml
classification:
  path_patterns:
    high_sensitivity:
      - "hr/**"
      - "**/salary*"
      - "**/payroll*"
  content_patterns:
    pii_fields: ["ssn", "social_security", "passport", "credit_card"]
```

### v0.3.0: Connector-Specific Classification
- HTTP proxy: classify by URL patterns + Content-Type header
- Database connector: classify by table schema + column names
- API connector: classify by endpoint path + OpenAPI spec

### v1.0.0+: ML-Based Classification (Non-Blocking)
- Train model on organizational data naming patterns
- Use ML only as advisory (never block solely on ML prediction)
- Keep deterministic rules as primary enforcement

## Trade-Offs

| Criterion          | Path-Based | Content-Based |
|--------------------|------------|---------------|
| Speed              | Fast       | Slow          |
| Accuracy           | ~70-80%    | ~90-95%       |
| Predictability     | High       | Low           |
| Implementation     | Simple     | Complex       |
| Dependencies       | None       | Parsing libs  |
| Failure modes      | Obvious    | Silent errors |

**Decision:** Optimize for simplicity and speed in MVP. Add accuracy in v0.2.0.

## Consequences

### Positive
- Fast implementation (1 day)
- Easy to test and reason about
- No external dependencies
- Proves enforcement semantics

### Negative
- Requires organizational naming conventions
- False negatives possible with obfuscated names
- Doesn't handle generic filenames like "data.csv"

### Mitigations
- Document naming best practices in CONTRIBUTING.md
- Add "Limitations" section to README.md
- Plan content-based classification for v0.2.0
- Encourage users to report false negatives as issues

## Examples

### Will Classify Correctly
```
✓ /hr/employees.csv              → high (HR)
✓ /payroll/salary_bands.csv      → high (HR)
✓ /data/customer_ssn.txt         → high (PII)
✓ /siem/incidents.json           → medium (security)
✓ /org/team_structure.txt        → low (default)
```

### Will Mis-Classify
```
✗ /finance/executive_comp.csv    → low (should be high, no "salary" keyword)
✗ /exports/emp_data.csv          → low (should be high, obfuscated)
✗ /reports/q4_summary.pdf        → low (may contain sensitive exec data)
```

For these cases, users should:
1. Rename files to match patterns (`exec_comp.csv` → `exec_salary.csv`)
2. Wait for v0.2.0 content-based classification
3. Report patterns as issues for inclusion in defaults

## References

- [OWASP Top 10 - A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [NIST SP 800-53 - AC-3 Access Enforcement](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [VaultSpectre naming patterns](https://github.com/ppiankov/vaultspectre) (similar path-based approach)
