# Fieldtest: Chainwatch Guard Perspective
# Shows enforcement decisions from the audit log after clawbot runs.
# Run AFTER release-agent.tape so the audit log exists.

Output fieldtest-guard.gif

Set Shell "bash"
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set FontSize 14
Set Padding 20

Sleep 1s
Type "bash internal/fieldtest/scripts/show-guard.sh"
Enter
Sleep 30s
