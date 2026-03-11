# Chainwatch Policy Gate Action

This GitHub Action runs `chainwatch` policy checks as a CI gate. It performs two types of checks:
1. **Certification**: Verifies a profile against a safety suite (enterprise/minimal).
2. **Scenario Check**: Runs custom scenario assertions from YAML files.

## Usage

```yaml
jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Policy Gate
        uses: ./.github/actions/policy-gate
        with:
          profile: 'customer-support'
          suite: 'enterprise'
          scenarios: 'tests/scenarios/*.yaml'
```

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `profile` | **Required** Profile to certify | `default` |
| `suite` | Certification suite (`minimal` or `enterprise`) | `enterprise` |
| `scenarios` | Glob pattern for scenario YAML files to check | `""` |
| `policy_path` | Path to custom policy YAML | `""` |
| `denylist_path` | Path to custom denylist YAML | `""` |
| `chainwatch_version` | Chainwatch version to install | `latest` |

## Outputs

| Name | Description |
|------|-------------|
| `certify_json` | JSON result from the `certify` command |
| `check_json` | JSON result from the `check` command |

## Step Summary

The action posts a markdown table to the GitHub Step Summary with the pass/fail status of the certification and scenarios.

## Artifacts

The action uploads `certify.json` and `check.json` as artifacts named `chainwatch-results`.
