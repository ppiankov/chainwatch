# Chainwatch Release Fieldtest — Proof of Enforcement
# Real clawbot agent binary + real chainwatch + real OpenClaw installation.
# Run: vhs internal/fieldtest/tapes/release.tape

Output fieldtest-demo.gif

Set Shell "bash"
Set Width 1200
Set Height 900
Set Theme "Dracula"
Set FontSize 14
Set Padding 20

Sleep 1s
Type "rm -f /tmp/release-fieldtest.jsonl"
Enter
Sleep 500ms
Type "./clawbot"
Enter
Sleep 45s
