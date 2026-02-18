# Fieldtest: Chainwatch Guard Perspective
# Shows real-time enforcement decisions from the audit log.
# Run AFTER release-agent.tape so the audit log exists.

Output fieldtest-guard.gif

Set Shell "bash"
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set FontSize 14
Set Padding 20

Sleep 1s
Type "echo '=== CHAINWATCH GUARD ==='"
Enter
Sleep 500ms
Type "echo 'Enforcement decisions from field test:'"
Enter
Sleep 500ms
Type "./chainwatch audit verify /tmp/release-fieldtest.jsonl"
Enter
Sleep 2s
Type "cat /tmp/release-fieldtest.jsonl | jq -r '\"[\" + (.decision | ascii_upcase) + \"] \" + .action.tool + \":\" + .action.resource + (if .reason != \"\" then \"  -- \" + .reason else \"\" end)'"
Enter
Sleep 10s
