# Fieldtest: Clawbot Agent Perspective
# Shows exactly what a user sees when they launch clawbot in their terminal.

Output fieldtest-agent.gif

Set Shell "bash"
Set Width 1200
Set Height 900
Set Theme "Dracula"
Set FontSize 14
Set Padding 20

Hide
Type "export GROQ_API_KEY=$(cat /tmp/.groq-key 2>/dev/null)"
Enter
Sleep 500ms
Type "clear"
Enter
Sleep 500ms
Show

Type "./clawbot"
Enter
Sleep 50s
