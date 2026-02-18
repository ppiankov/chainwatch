# Fieldtest: Clawbot Agent Perspective
# Shows the real clawbot agent receiving a mission and attempting tool calls.
# Chainwatch blocks dangerous commands, allows safe ones.

Output fieldtest-agent.gif

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
