# Chainwatch Release Fieldtest — Proof of Enforcement
# Attached to every GitHub Release as fieldtest-demo.gif.
# Shows clawbot agent receiving a mission brief with hazardous instructions,
# chainwatch blocking dangerous commands while allowing safe ones.
# Run: vhs internal/fieldtest/tapes/release.tape

Output fieldtest-demo.gif

Set Shell "bash"
Set Width 1200
Set Height 900
Set Theme "Dracula"
Set FontSize 14
Set Padding 20

Type "rm -f /tmp/release-fieldtest.jsonl"
Enter
Sleep 500ms

Type "bash internal/fieldtest/scripts/agent-sim.sh"
Enter
Sleep 45s
