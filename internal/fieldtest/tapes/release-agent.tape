# Fieldtest: Clawbot Agent Perspective
# Shows exactly what a user sees when they launch clawbot in their terminal.
# GROQ_API_KEY is loaded from /tmp/.groq-key (written by CI) via hidden export.

Output fieldtest-agent.gif

Set Shell "bash"
Set Width 1200
Set Height 900
Set Theme "Dracula"
Set FontSize 14
Set Padding 20

# Export API key in bash session (hidden from recording)
Hide
Type "export GROQ_API_KEY=$(cat /tmp/.groq-key 2>/dev/null)"
Enter
Sleep 1s
Type "clear"
Enter
Sleep 500ms
Show

Sleep 1s
Type "./clawbot"
Enter
Sleep 50s
