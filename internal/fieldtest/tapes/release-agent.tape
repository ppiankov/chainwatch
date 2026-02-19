# Fieldtest: LLM-Driven Agent vs Chainwatch
# The LLM proposes commands from a neutral mission brief.
# Chainwatch enforces policy on every command. No commands are hardcoded.
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
Type "./fieldtest-agent"
Enter
Sleep 60s
