# Chainwatch Release Fieldtest — Split-Screen Proof of Enforcement
# Left pane: real clawbot agent (OpenClaw + chainwatch guardrail)
# Right pane: real chainwatch audit log with live enforcement decisions
# Run: vhs internal/fieldtest/tapes/release.tape

Output fieldtest-demo.gif

Set Shell "bash"
Set Width 1400
Set Height 900
Set Theme "Dracula"
Set FontSize 13
Set Padding 10

Type "bash internal/fieldtest/scripts/release-demo.sh"
Enter
Sleep 55s
