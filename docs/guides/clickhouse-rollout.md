# ClickHouse Multi-Cluster Rollout Guide

This guide covers the deployment of nullbot for automated observation and drift detection across a multi-cluster ClickHouse fleet. The architecture utilizes AWS Bedrock for LLM-based classification and integrates pastewatch for credential protection in interactive sessions.

## Overview

Deploying nullbot provides continuous visibility into ClickHouse operational health and configuration consistency. The rollout ensures that evidence collected from database nodes is redacted before being processed by LLM providers, maintaining security boundaries while enabling intelligent analysis.

Key components:
- nullbot: Collection agent running observation runbooks.
- orchestrator: Dispatcher for findings, JIRA ticketing, and Slack notifications.
- AWS Bedrock: Claude Haiku backend for classifying finding severity and intent.
- pastewatch: Credential redaction for XML and interactive sessions.
- Pipeline Redaction: Rule-based redaction of passwords and hostnames from observation evidence.

## Prerequisites

- chainwatch and nullbot binaries installed on a central orchestration host.
- AWS account with Bedrock access (Claude Haiku model enabled).
- EC2 instance (orchestration host) in the same VPC as ClickHouse nodes.
- SSH key pair for the `nullbot` user, distributed to all ClickHouse nodes.
- pastewatch version >= 0.19.4 for XML value-aware credential redaction.
- Access to a Git repository containing the baseline ClickHouse configuration (users.d/ and config.d/).

## Infrastructure Setup

### 1. ClickHouse Node Preparation

On each ClickHouse node, create a dedicated system user for nullbot:

```bash
# Create nullbot user without sudo or shell access requirements
sudo useradd -m -s /bin/bash nullbot
sudo mkdir -p /home/nullbot/.ssh
sudo chmod 700 /home/nullbot/.ssh

# Authorize the orchestration host's SSH key
echo "ssh-ed25519 AAAAC3..." | sudo tee /home/nullbot/.ssh/authorized_keys
sudo chown -R nullbot:nullbot /home/nullbot/.ssh
```

Grant read-only filesystem access to configuration directories:

```bash
sudo setfacl -R -m u:nullbot:r /etc/clickhouse-server/users.d/
sudo setfacl -R -m u:nullbot:r /etc/clickhouse-server/config.d/
```

### 2. ClickHouse Database Access

Create a read-only user within ClickHouse for system table queries:

```sql
CREATE USER nullbot IDENTIFIED WITH no_password;
GRANT SELECT ON system.* TO nullbot;
```

### 3. AWS Infrastructure

Assign an IAM role to the orchestration host with the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "bedrock:InvokeModel",
            "Resource": [
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-*"
            ]
        }
    ]
}
```

Configure a VPC Interface Endpoint for Bedrock Runtime (`com.amazonaws.{region}.bedrock-runtime`) to ensure traffic remains within the AWS network.

## Inventory Configuration

Create an `inventory.yaml` file to define your fleet. This file acts as the source of truth for all clusters and schedules.

```yaml
clickhouse:
  clusters:
    - name: dev-cluster
      hosts:
        - dev-ch-01.internal
        - dev-ch-02.internal
      config_repo: /opt/configs/clickhouse-dev
      config_path: users.d/
      ssh_user: nullbot
      clickhouse_port: 9000
    - name: prod-cluster
      hosts:
        - prod-ch-01.internal
        - prod-ch-02.internal
        - prod-ch-03.internal
      config_repo: /opt/configs/clickhouse-prod
      config_path: users.d/
      ssh_user: nullbot
      clickhouse_port: 9000

bedrock:
  region: us-east-1
  vpc_endpoint: true
  models:
    nullbot_analysis: anthropic.claude-3-haiku-20240307-v1:0
  iam_role: arn:aws:iam::123456789012:role/nullbot-orchestrator

orchestrator:
  jira:
    project: INFRA
    base_url: https://your-domain.atlassian.net
    token_env: JIRA_API_TOKEN
  dispatch:
    backend: local

notifications:
  slack:
    webhook_env: SLACK_WEBHOOK_URL
    channel: "#infra-ops"
    critical_channel: "#infra-critical"

schedules:
  - name: hourly-ops
    types: [clickhouse]
    interval: "0 * * * *"
    enabled: true
  - name: drift-check
    types: [clickhouse-config]
    interval: "0 */6 * * *"
    enabled: true
```

## Credential Protection

The system employs two layers of protection to prevent credentials from reaching the LLM or being exposed to operators.

### 1. Pipeline Redaction

The `RedactRules` engine automatically filters evidence collected by nullbot. It targets common ClickHouse XML patterns and generic secrets.

Example Redaction:
**Before Redaction (Raw Evidence):**
```xml
<users>
    <readonly>
        <password>mypassword123</password>
        <networks>
            <ip>::/0</ip>
        </networks>
    </readonly>
</users>
```

**After Redaction (Sent to Bedrock):**
```xml
<users>
    <readonly>
        <password>[REDACTED]</password>
        <networks>
            <ip>::/0</ip>
        </networks>
    </readonly>
</users>
```

### 2. Pastewatch (WO-68)

For interactive sessions where an operator uses `orchestrator view` or `orchestrator inspect`, the pastewatch integration uses an XML-aware parser to redact sensitive values in real-time, even if the LLM classification suggests the content is safe for local viewing.

## Staged Rollout

### Stage 1: Dev Cluster Dry-Run
**Duration:** 48 Hours
- Deploy to `dev-cluster` with `enabled: true` in inventory.
- Run manually: `nullbot observe --inventory inventory.yaml --cluster dev-cluster`.
- Verify that `orchestrator dispatch` creates local logs but no JIRA tickets (use a dummy JIRA project or local dispatch).
- Review `RedactEvidence` logs to ensure no passwords escaped redaction.

### Stage 2: Dev Cluster Live
**Duration:** 72 Hours
- Enable JIRA and Slack notifications for the dev cluster.
- Verify that `clickhouse-config` drift detection correctly identifies differences between the local XML baseline and live ClickHouse state.
- Pass criteria: 0 false positives in classification; 100% redaction of test credentials.

### Stage 3: Canary Prod Cluster
**Duration:** 1 Week
- Add a single host from the `prod-cluster` to a new `prod-canary` cluster in inventory.
- Run hourly operational checks.
- Pass criteria: Stable operation without Bedrock timeouts; Slack alerts routed correctly by severity.

### Stage 4: Full Prod Rollout
- Add remaining production clusters one at a time.
- Wait 24 hours between cluster additions to monitor for alert fatigue.
- Verify CloudTrail logs to confirm all Bedrock API calls originate from the authorized VPC endpoint.

## Schedule Installation

Use the `orchestrator schedule` command to generate the appropriate installation format for your environment.

### Using Crontab
Generate and install to `/etc/cron.d/nullbot`:
```bash
orchestrator schedule --inventory inventory.yaml --format crontab > /tmp/nullbot-cron
sudo mv /tmp/nullbot-cron /etc/cron.d/nullbot
```

### Using Systemd Timers
Generate systemd unit files:
```bash
orchestrator schedule --inventory inventory.yaml --format systemd
```
Copy the output `nullbot-*.timer` and `nullbot-*.service` files to `/etc/systemd/system/`, then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nullbot-hourly-ops.timer
```

## Monitoring and Verification

- **Pipeline Health:** Use `orchestrator metrics` to monitor the number of findings processed and LLM token usage.
- **Drift Verification:** Use `orchestrator verify --wo WO-xxx` after a remediation PR has been merged to confirm the drift is resolved.
- **Audit:** Query AWS CloudTrail for `InvokeModel` events to inspect the prompt structure (ensure `[REDACTED]` tokens are present).

## Rollback

To stop observation for a cluster:
1. Remove the cluster entry from `inventory.yaml`.
2. Re-run `orchestrator schedule` and update the cron/systemd configuration.
3. Reload the scheduler (e.g., `systemctl daemon-reload`).

The system is stateless regarding ClickHouse; removing a cluster will stop all collection and analysis without affecting database performance.

## Troubleshooting

- **SSH Connectivity:** Ensure the orchestration host's public key is in `/home/nullbot/.ssh/authorized_keys` and the user has read access to `/etc/clickhouse-server/`.
- **Bedrock Timeouts:** Check VPC endpoint health. If timeouts persist, consider switching to a region with higher Haiku throughput limits.
- **Redaction False Negatives:** If a secret pattern is missed, update `internal/observe/redact.go` with a new `RedactRule` and redeploy the nullbot binary.
- **Stale PRs:** If `clickhouse-config` identifies drift but no PR is created, verify the `config_repo` path is writable by the orchestrator process.
