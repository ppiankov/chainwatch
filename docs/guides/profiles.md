# Chainwatch Profiles Guide

Profiles are reusable, opinionated safety bundles for AI agents. Each profile defines authority boundaries (what instructions the agent can receive), execution boundaries (what commands/files/URLs it can access), and policy overrides (what resource patterns to allow, deny, or require approval for).

Profiles compose with your base configuration: execution boundaries merge into the denylist (additive only), policy rules prepend to your config rules (first-match-wins priority), and min_tier promotes the effective tier (never demotes).

## When to Use Profiles

- **Code-generation agents** — Use `coding-agent` to block production deployments, package publishes, and credential access while allowing development workflow
- **Terraform planners** — Use `terraform-planner` to allow read-only IaC operations (plan, validate) while blocking apply/destroy
- **Customer support** — Use `customer-support` to block account deletion, payment modifications, and PII export
- **Read-only analysis** — Use `research-agent` or `finops` for zero-write enforcement with read-only access
- **Browser automation** — Use `clawbot` or `vm-cloud` for web-scraper agents with payment/checkout protection

## Built-in Profiles Reference

| Profile | Description | min_tier | Key Authority Boundaries | Key Execution Boundaries | Recommended Use Case |
|---------|-------------|----------|--------------------------|-------------------------|----------------------|
| **clawbot** | Safety profile for browser-automation AI agents (Clawbot-style) | 0 (default) | Cross-context injection, authority escalation, prompt injection, safety bypass | checkout/payment URLs, credential files, shell pipe downloads, sudo | Browser automation agents that need read-only web access but must never touch payments or credentials |
| Example: `chainwatch exec --profile clawbot -- python scraper.py` |
| **coding-agent** | Safety profile for code-generation and development AI agents | 0 (default) | Production deployment, kubectl apply, database migrations, schema modification, package publish | Deploy/release URLs, .env files, credential files, SSH/AWS/GCloud dirs, rm -rf, npm publish, terraform apply, docker push | Code-generation agents (Aider, OpenHands, Cursor) that write code but must never deploy to production or publish packages |
| Example: `chainwatch exec --profile coding-agent -- aider --model gpt-4` |
| **customer-support** | Safety profile for customer-facing support AI agents | 0 (default) | Account deletion, payment/refund/billing, PII export, admin access, policy override | Admin/internal URLs, billing/payment APIs, bulk export, database files, SSH/AWS dirs, sudo, curl, database CLIs | Customer support agents that can look up user data but must never delete accounts, process payments, or export PII |
| Example: `chainwatch exec --profile customer-support -- python support_bot.py` |
| **data-analyst** | Safety profile for data analysis and reporting AI agents | 0 (default) | Destructive SQL (DELETE/DROP/TRUNCATE/ALTER), INSERT/UPDATE writes, external data egress, arbitrary command execution | Upload/send URLs, admin/checkout/payment URLs, .env/credential files, SSH/AWS dirs, curl/wget, scp/rsync, rm -rf, sudo, ssh | Data analysis agents that query databases and generate reports but must never modify data or transmit externally |
| Example: `chainwatch exec --profile data-analyst -- python analyze_data.py` |
| **terraform-planner** | Terraform planning profile for execution agents that must never apply | 2 (guarded) | terraform apply/destroy/import, auto-approval flags, kubectl apply/delete | Settings/secrets URLs, .env/credential files, SSH/AWS dirs, terraform apply/destroy/import, kubectl apply/delete, -auto-approve | IaC agents that plan infrastructure changes but must never execute apply/destroy operations |
| Example: `chainwatch exec --profile terraform-planner -- terraform plan` |
| **sre-infra** | IaC-only safety profile for SRE infrastructure agents | 2 (guarded) | Manual config edits, direct SSH, IaC bypass attempts, prompt injection, direct hotfixes, manual package installs | Admin/checkout/payment URLs, SSH/AWS credential files, systemctl/service, package managers (apt/yum), docker run/exec, rm -rf, shell pipe downloads, sudo su, chmod 777 | SRE agents that manage infrastructure through IaC only, never via direct SSH or manual edits |
| Example: `chainwatch exec --profile sre-infra -- ansible-playbook site.yml` |
| **finops** | Read-only safety profile for cost analysis and FinOps AI agents | 2 (guarded) | Delete/terminate/destroy, create/provision/launch/deploy, modify/update/write/apply, scale/resize, data egress, prompt injection | API write/delete URLs, upload/send URLs, checkout/payment/oauth URLs, .env/credential files, SSH/AWS dirs, rm/mv, sudo, ssh/scp, terraform apply/destroy, kubectl delete/apply/edit, AWS instance commands | Cost analysis agents that inspect cloud resources and generate reports but must never create, modify, or terminate resources |
| Example: `chainwatch exec --profile finops -- python cost_report.py` |
| **research-agent** | Read-only safety profile for research and analysis AI agents | 2 (guarded) | Write/delete/create/modify/update/insert/drop/alter, command execution, external communication, upload/export/transmit | API write/delete URLs, upload/send URLs, checkout/payment URLs, .env/credential files, SSH/AWS dirs, rm/mv/cp, curl/wget/scp/rsync, sudo, chmod/chown | Research agents that analyze codebases and documentation but must never write files or execute commands |
| Example: `chainwatch exec --profile research-agent -- python analyze_repo.py` |
| **vm-cloud** | VM/container deployment — no local LLM, mandatory redaction, observe-only | 2 (guarded) | Cross-context injection, authority escalation, prompt injection, safety bypass, write/modify/delete/create/update | checkout/payment URLs, stripe/paypal, oauth/token, account/delete, SSH/AWS dirs, .env/credential files, rm -rf, shell pipe downloads, sudo, systemctl/service, package managers, pip install | VM/container deployment environments where agents observe and report but must never modify state or access local credentials |
| Example: `chainwatch exec --profile vm-cloud -- python observer.py` |

## Profile Anatomy

A profile is a YAML file with the following structure:

```yaml
name: my-profile                    # Required: profile name
description: What this profile does # Required: human-readable description
min_tier: 2                         # Optional: 0=safe, 1=elevated, 2=guarded, 3=critical (default: 0)

# Authority boundaries — instruction-level regex patterns
# Checked via MatchesAuthority() when instruction text is available
# Fail-closed: invalid regex blocks as a match
authority_boundaries:
  - pattern: "deploy.*prod"        # Regex pattern (case-insensitive)
    reason: "Production deployment requires human approval"
  - pattern: "kubectl\\s+apply"
    reason: "Kubernetes cluster modification blocked"
  - pattern: "ALTER\\s+TABLE"      # Must escape backslashes in YAML
    reason: "Schema modification blocked"

# Execution boundaries — merged into denylist via AddPattern()
# Additive only: profile cannot remove existing denylist patterns
execution_boundaries:
  urls:
    - "*/deploy*"                   # Wildcard pattern: matches any URL containing "/deploy"
    - "*/settings/secrets*"         # Wildcard pattern: matches any URL with "/settings/secrets"
    - "api.example.com/v1/keys"     # Exact pattern: matches this specific URL
  files:
    - "**/.env"                     # Glob pattern: matches any .env file anywhere
    - "**/credentials*"             # Glob pattern: matches any file with "credentials" in name
    - "~/.ssh/*"                    # Glob pattern: matches all SSH config files
    - "/etc/passwd"                 # Exact path: matches this specific file
  commands:
    - "rm -rf"                      # Substring match: matches any command containing "rm -rf"
    - "kubectl apply"               # Substring match: matches any command containing "kubectl apply"
    - "terraform apply"             # Substring match: matches any command containing "terraform apply"

# Policy rules — prepended to config rules (first-match-wins)
# Optional: omit if no policy overrides needed
policy:
  rules:
    - purpose: "*"                  # Wildcard: applies to all purposes
      resource_pattern: "*credentials*"  # Glob pattern: matches any resource with "credentials"
      decision: deny                # Valid decisions: allow, deny, require_approval, redact
      reason: "credential access blocked by my-profile"
    - purpose: "database-read"      # Specific purpose: only applies when purpose=database-read
      resource_pattern: "*.csv"     # Glob pattern: matches any CSV file
      decision: allow                # Allows this resource pattern for this purpose
      reason: "CSV export allowed for database-read purpose"
    - purpose: "*"
      resource_pattern: "*salary*"
      decision: require_approval    # Requires human approval before access
      reason: "salary data requires approval per my-profile"
```

### Tier System

The `min_tier` field sets the minimum safety tier for all actions. Actions classified below this tier are promoted up (never demoted):

- **Tier 0 (safe)** — Allow with minimal logging. Confirmed-safe actions: reading README files, listing directories, running `git status`
- **Tier 1 (elevated)** — Allow with detailed logging. Unknown actions default to this tier
- **Tier 2 (guarded)** — Require human approval before proceeding. Infrastructure read-only, IaC planning, cost analysis
- **Tier 3 (critical)** — Deny by default. Production deployments, credential access, destructive operations

In guarded mode (default):
- Tier 0-1: Allow
- Tier 2: Require approval
- Tier 3: Deny

Profiles with `min_tier: 2` (terraform-planner, sre-infra, finops, research-agent, vm-cloud) promote all actions to at least tier 2, requiring approval for anything that would normally be allowed.

## Creating Custom Profiles

### Step 1: Create the profile file

Create `~/.chainwatch/profiles/my-profile.yaml`:

```bash
mkdir -p ~/.chainwatch/profiles
nano ~/.chainwatch/profiles/my-profile.yaml
```

### Step 2: Start from a built-in profile

Copy the closest built-in profile and modify:

```bash
# Find the built-in profile
chainwatch profile list

# Copy it (example: coding-agent)
cp $(chainwatch profile path coding-agent) ~/.chainwatch/profiles/my-profile.yaml

# Edit it
nano ~/.chainwatch/profiles/my-profile.yaml
```

### Step 3: Customize the profile

Edit the fields for your use case:

```yaml
name: triage-bot
description: Read-only triage bot for GitHub issue analysis
min_tier: 1  # Promote unknown actions to elevated

authority_boundaries:
  - pattern: "write|delete|modify|create"
    reason: "Write operations blocked for triage bot"
  - pattern: "git push"
    reason: "Git push blocked for triage bot"

execution_boundaries:
  urls:
    - "*/api/3/repos/*"  # Block GitHub API write endpoints
  files:
    - "~/.ssh/*"         # Block SSH keys
    - "**/.env"          # Block environment files
  commands:
    - "git push"          # Block git push
    - "rm -rf"            # Block destructive commands
```

### Step 4: Test with dry-run

Verify the profile works without executing:

```bash
# Test a blocked command
chainwatch exec --profile triage-bot --dry-run -- git push
# Decision: deny | Reason: Denylisted: command matches pattern: git push

# Test an allowed command
chainwatch exec --profile triage-bot --dry-run -- git log
# Decision: allow | Reason: tier 0 (safe) in guarded mode
```

### Step 5: Certify the profile

Validate the profile against the certification suite:

```bash
# Run minimal suite (quick validation)
chainwatch certify --profile triage-bot --suite minimal

# Run enterprise suite (comprehensive validation)
chainwatch certify --profile triage-bot --suite enterprise
```

The certification suite tests:
- Authority boundary regex patterns compile correctly
- Execution boundary patterns are valid (URLs are regex, files are globs, commands are substrings)
- Policy rules have valid decision types (allow, deny, require_approval, redact)
- min_tier is in valid range (0-3)

### Step 6: Use the profile

Apply the profile to an agent:

```bash
# For CLI execution
chainwatch exec --profile triage-bot -- python triage_bot.py

# For init command (set default)
chainwatch init --profile triage-bot

# For Claude Code hook
chainwatch hook install --profile triage-bot
```

## Profile + Preset Composition

Profiles and presets compose additively. Both add patterns to the denylist, neither removes existing patterns.

### Composition Rules

1. **Execution boundaries merge into denylist** — Profile `execution_boundaries` patterns are added to `denylist.yaml` via `AddPattern()` (additive only, no removal)
2. **Preset patterns also merge into denylist** — Preset patterns (e.g., supply-chain) are also added via `AddPattern()`
3. **Combined denylist** — Both profile and preset patterns are checked during denylist evaluation
4. **Policy rules prepend** — Profile `policy.rules` are prepended to `policy.yaml` rules (first-match-wins priority)
5. **min_tier promotes** — Profile `min_tier` raises the effective tier (never demotes)

### Example: Profile + Preset

```bash
# Initialize with profile + preset
chainwatch init --profile coding-agent --preset supply-chain
```

Result:
- Profile adds coding-agent execution boundaries (rm -rf, npm publish, terraform apply, credential files)
- Preset adds supply-chain patterns (pip --index-url from untrusted sources, cargo publish, docker push)
- Combined denylist blocks both sets of patterns
- Profile policy rules prepend to base config rules
- min_tier from profile (0) applies

### Order of Operations

During `chainwatch init --profile <name> --preset <preset>`:

1. Load base denylist (default patterns)
2. Merge preset patterns into denylist
3. Load profile, merge profile execution boundaries into denylist
4. Load base policy config
5. Apply profile to policy (prepend rules, set min_tier)
6. Write final denylist.yaml and policy.yaml

## Common Patterns

### Pattern 1: Restrict agent to read-only operations

Create a profile that blocks all write operations:

```yaml
name: read-only-agent
description: Read-only agent with zero write enforcement
min_tier: 2  # Promote to guarded for stricter enforcement

authority_boundaries:
  - pattern: "write|delete|create|modify|update|insert|drop|alter"
    reason: "Write operations blocked for read-only agent"
  - pattern: "rm |mv |cp "
    reason: "File modification commands blocked"

execution_boundaries:
  commands:
    - "rm "
    - "mv "
    - "cp "
    - "touch "
    - "echo "
    - "cat >"
    - "tee "
    - "chmod "
    - "chown "
  urls:
    - "*/api/write*"
    - "*/api/delete*"
    - "*/api/update*"
```

Test:

```bash
chainwatch exec --profile read-only-agent --dry-run -- rm file.txt
# Decision: deny | Reason: Denylisted: command matches pattern: rm

chainwatch exec --profile read-only-agent --dry-run -- cat file.txt
# Decision: allow | Reason: tier 0 (safe) in guarded mode
```

### Pattern 2: Allow terraform plan but block apply

Create a profile that allows planning but blocks execution:

```yaml
name: terraform-readonly
description: Terraform read-only — allow plan, block apply/destroy
min_tier: 2  # Promote to guarded

authority_boundaries:
  - pattern: "terraform\\s+(apply|destroy|import|refresh)"
    reason: "Terraform write operations blocked"
  - pattern: "auto-approve"
    reason: "Auto-approval blocked"

execution_boundaries:
  commands:
    - "terraform apply"
    - "terraform destroy"
    - "terraform import"
    - "terraform refresh"
    - "-auto-approve"
    - "--auto-approve"

policy:
  rules:
    - purpose: "*"
      resource_pattern: "*terraform plan*"
      decision: allow
      reason: "terraform plan allowed for read-only agent"
    - purpose: "*"
      resource_pattern: "*terraform validate*"
      decision: allow
      reason: "terraform validate allowed for read-only agent"
    - purpose: "*"
      resource_pattern: "*terraform fmt*"
      decision: allow
      reason: "terraform fmt allowed for read-only agent"
```

Test:

```bash
chainwatch exec --profile terraform-readonly --dry-run -- terraform plan
# Decision: allow | Reason: Policy rule match: terraform plan allowed

chainwatch exec --profile terraform-readonly --dry-run -- terraform apply
# Decision: deny | Reason: Denylisted: command matches pattern: terraform apply
```

### Pattern 3: Block all external HTTP except specific APIs

Create a profile that blocks HTTP except for allowlisted APIs:

```yaml
name: http-restricted
description: Block all HTTP except specific API allowlist

execution_boundaries:
  urls:
    - "*"  # Block all URLs by default

policy:
  rules:
    - purpose: "*"
      resource_pattern: "*api.internal.company.com/*"
      decision: allow
      reason: "Internal API access allowed"
    - purpose: "*"
      resource_pattern: "*github.com/api/*"
      decision: allow
      reason: "GitHub API access allowed"
    - purpose: "*"
      resource_pattern: "*"
      decision: deny
      reason: "External HTTP blocked by http-restricted profile"
```

Test:

```bash
chainwatch exec --profile http-restricted --dry-run -- curl https://api.internal.company.com/data
# Decision: allow | Reason: Policy rule match: Internal API access allowed

chainwatch exec --profile http-restricted --dry-run -- curl https://example.com/data
# Decision: deny | Reason: Policy rule match: External HTTP blocked
```

### Pattern 4: Block credential file access for triage bots

Create a profile for triage/analysis bots that must never access credentials:

```yaml
name: triage-readonly
description: Triage bot with credential access blocked

authority_boundaries:
  - pattern: "credential|password|secret|token|key"
    reason: "Credential-related instructions blocked"

execution_boundaries:
  files:
    - "**/.env"
    - "**/.env.*"
    - "**/credentials*"
    - "**/secrets*"
    - "**/tokens*"
    - "~/.ssh/*"
    - "~/.aws/*"
    - "~/.gcloud/*"
    - "~/.azure/*"
    - "**/api_keys*"
    - "**/private_key*"

policy:
  rules:
    - purpose: "*"
      resource_pattern: "*password*"
      decision: deny
      reason: "credential access blocked by triage-readonly"
    - purpose: "*"
      resource_pattern: "*secret*"
      decision: deny
      reason: "secret access blocked by triage-readonly"
    - purpose: "*"
      resource_pattern: "*credential*"
      decision: deny
      reason: "credential access blocked by triage-readonly"
```

Test:

```bash
chainwatch exec --profile triage-readonly --dry-run -- cat .env
# Decision: deny | Reason: Denylisted: file matches pattern: **/.env

chainwatch exec --profile triage-readonly --dry-run -- grep "TODO" README.md
# Decision: allow | Reason: tier 0 (safe) in guarded mode
```

## Testing and Validation

### Dry-run Testing

Test commands without executing:

```bash
# Test a specific command with profile
chainwatch exec --profile my-profile --dry-run -- <command>

# Test multiple commands in a script
chainwatch exec --profile my-profile --dry-run -- bash script.sh

# Test with specific purpose (if agent identity is configured)
chainwatch exec --profile my-profile --dry-run --agent my-agent --purpose database-read -- psql -c "SELECT * FROM users"
```

### Certification Suite

Validate profile correctness:

```bash
# Minimal suite (quick validation of profile structure)
chainwatch certify --profile my-profile --suite minimal

# Enterprise suite (comprehensive validation with test scenarios)
chainwatch certify --profile my-profile --suite enterprise

# With custom policy/denylist paths
chainwatch certify --profile my-profile --policy /path/to/policy.yaml --denylist /path/to/denylist.yaml --suite enterprise
```

Certification validates:
- Profile YAML parses correctly
- Authority boundary regex patterns compile (case-insensitive `(?i)` prefix added automatically)
- Execution boundary patterns are valid for their category
- Policy rules have valid decision types
- min_tier is in valid range (0-3)

### Custom Scenario Files

Create test scenarios to verify profile behavior:

```yaml
# test-scenarios.yaml
scenarios:
  - name: "Block production deployment"
    instruction: "deploy to production"
    expected_decision: deny
    expected_reason: "Production deployment requires human approval"

  - name: "Allow terraform plan"
    command: "terraform plan"
    expected_decision: allow
    expected_reason: "Policy rule match: terraform plan allowed"

  - name: "Block credential access"
    file_path: "/home/user/.env"
    expected_decision: deny
    expected_reason: "Denylisted: file matches pattern: **/.env"
```

Run scenarios (future feature):

```bash
chainwatch certify --profile my-profile --scenarios test-scenarios.yaml
```

### Authority Boundary Testing

Test instruction-level patterns:

```bash
# Test instruction text directly (simulates agent receiving instruction)
echo "deploy to production" | chainwatch exec --profile my-profile --dry-run -- cat
# Decision: deny | Reason: Authority boundary match: Production deployment requires human approval
```

Authority boundaries are checked via `MatchesAuthority()` when instruction text is available. Invalid regex patterns fail-closed (treated as a match).

## Troubleshooting

### Profile not found

```bash
chainwatch exec --profile my-profile -- echo "test"
# Error: profile "my-profile" not found
```

**Solution:** Ensure the profile file exists at `~/.chainwatch/profiles/my-profile.yaml` or use a built-in name.

### Invalid regex pattern

```bash
chainwatch certify --profile my-profile --suite minimal
# Error: authority_boundaries[2]: invalid regex "[(?test]": error parsing regexp
```

**Solution:** Fix the regex pattern in your profile YAML. Use `\\` to escape backslashes: `"ALTER\\s+TABLE"`.

### Denylist pattern not matching

```bash
chainwatch exec --profile my-profile --dry-run -- curl https://example.com/api/data
# Decision: allow (expected deny)
```

**Solution:** Check that denylist pattern uses correct syntax:
- URLs: regex patterns (e.g., `"*/api/write*"` uses wildcard, but internally compiled as regex)
- Files: glob patterns (e.g., `"**/.env"`)
- Commands: substring match (e.g., `"rm -rf"` matches any command containing that substring)

### Policy rule not matching

```bash
chainwatch exec --profile my-profile --dry-run -- cat credentials.json
# Decision: allow (expected deny)
```

**Solution:** Ensure policy rules are correctly formatted:
- `purpose`: `"*"` for all purposes, or specific purpose name (e.g., `"database-read"`)
- `resource_pattern`: glob pattern (e.g., `"*credentials*"`)
- `decision`: one of `allow`, `deny`, `require_approval`, `redact`
- Profile rules prepend to config rules, but first-match-wins means earlier rules take priority

## Next Steps

- **Choose a built-in profile** — Use `chainwatch profile list` to see all available profiles
- **Create custom profiles** — Follow the step-by-step guide above
- **Test with dry-run** — Validate profile behavior before production use
- **Certify profiles** — Run `chainwatch certify --profile <name>` before deployment
- **Combine with presets** — Add supply-chain protection with `--preset supply-chain`
- **Integration guides** — See [Getting Started](getting-started.md) for Claude Code, MCP, and SDK integration
- **Policy configuration** — See [boundary-configuration.md](../boundary-configuration.md) for advanced customization
