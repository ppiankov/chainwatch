#!/bin/bash
set -e

# Inputs
PROFILE="${1:-default}"
SUITE="${2:-enterprise}"
SCENARIOS="$3"
POLICY_PATH="$4"
DENYLIST_PATH="$5"
VERSION="${6:-latest}"

# Install chainwatch
if ! command -v chainwatch &> /dev/null; then
  echo "Installing chainwatch version: $VERSION"
  if [ "$VERSION" = "latest" ]; then
    go install github.com/ppiankov/chainwatch/cmd/chainwatch@latest
  else
    # Try curl from releases, fallback to go install
    BINARY_URL="https://github.com/ppiankov/chainwatch/releases/download/$VERSION/chainwatch-linux-amd64"
    if curl -sL --fail "$BINARY_URL" -o /usr/local/bin/chainwatch; then
      chmod +x /usr/local/bin/chainwatch
    else
      echo "Failed to download from releases, trying go install..."
      go install "github.com/ppiankov/chainwatch/cmd/chainwatch@$VERSION"
    fi
  fi
fi

echo "### Chainwatch Policy Gate" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

EXIT_CODE=0

# Run certify
echo "Running certify: profile=$PROFILE, suite=$SUITE"
CERTIFY_ARGS="--profile $PROFILE --suite $SUITE --format json"
if [ -n "$POLICY_PATH" ]; then CERTIFY_ARGS="$CERTIFY_ARGS --policy $POLICY_PATH"; fi
if [ -n "$DENYLIST_PATH" ]; then CERTIFY_ARGS="$CERTIFY_ARGS --denylist $DENYLIST_PATH"; fi

set +e
CERT_OUT=$(chainwatch certify $CERTIFY_ARGS)
CERT_STATUS=$?
set -e

if [ $CERT_STATUS -ne 0 ]; then
  EXIT_CODE=1
fi

# Run check
CHECK_OUT=""
CHECK_STATUS=0
if [ -n "$SCENARIOS" ]; then
  echo "Running check: scenarios=$SCENARIOS"
  CHECK_ARGS="--scenario $SCENARIOS --format json"
  if [ -n "$POLICY_PATH" ]; then CHECK_ARGS="$CHECK_ARGS --policy $POLICY_PATH"; fi
  if [ -n "$DENYLIST_PATH" ]; then CHECK_ARGS="$CHECK_ARGS --denylist $DENYLIST_PATH"; fi

  set +e
  CHECK_OUT=$(chainwatch check $CHECK_ARGS)
  CHECK_STATUS=$?
  set -e

  if [ $CHECK_STATUS -ne 0 ]; then
    EXIT_CODE=1
  fi
fi

# Format results for Step Summary
echo "#### Certification Results" >> $GITHUB_STEP_SUMMARY
echo "| Suite | Profile | Total | Passed | Failed | Status |" >> $GITHUB_STEP_SUMMARY
echo "|-------|---------|-------|--------|--------|--------|" >> $GITHUB_STEP_SUMMARY

# Parse JSON using python (since it's likely available in GH actions)
# certify output is a single object
python3 -c "
import json, sys
try:
    data = json.loads(sys.argv[1])
    passed = data.get('passed', 0)
    failed = data.get('failed', 0)
    total = data.get('total', 0)
    status = '✅' if failed == 0 else '❌'
    print(f'| $SUITE | $PROFILE | {total} | {passed} | {failed} | {status} |')
except Exception as e:
    print(f'| $SUITE | $PROFILE | ? | ? | ? | Error parsing |')
" "$CERT_OUT" >> $GITHUB_STEP_SUMMARY

if [ -n "$CHECK_OUT" ]; then
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "#### Scenario Check Results" >> $GITHUB_STEP_SUMMARY
  echo "| Scenario | Total | Passed | Failed | Status |" >> $GITHUB_STEP_SUMMARY
  echo "|----------|-------|--------|--------|--------|" >> $GITHUB_STEP_SUMMARY
  
  # check output is a list of objects
  python3 -c "
import json, sys
try:
    results = json.loads(sys.argv[1])
    for data in results:
        name = data.get('name', 'unnamed')
        passed = data.get('passed', 0)
        failed = data.get('failed', 0)
        total = data.get('total', 0)
        status = '✅' if failed == 0 else '❌'
        print(f'| {name} | {total} | {passed} | {failed} | {status} |')
except Exception as e:
    print(f'| Error | ? | ? | ? | {e} |')
" "$CHECK_OUT" >> $GITHUB_STEP_SUMMARY
fi

# Upload artifacts (handled by action.yml)
echo "certify_json<<EOF" >> $GITHUB_OUTPUT
echo "$CERT_OUT" >> $GITHUB_OUTPUT
echo "EOF" >> $GITHUB_OUTPUT

if [ -n "$CHECK_OUT" ]; then
  echo "check_json<<EOF" >> $GITHUB_OUTPUT
  echo "$CHECK_OUT" >> $GITHUB_OUTPUT
  echo "EOF" >> $GITHUB_OUTPUT
fi

exit $EXIT_CODE
