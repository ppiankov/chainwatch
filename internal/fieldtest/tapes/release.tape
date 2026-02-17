# Chainwatch Release Fieldtest — Split-Screen Proof of Enforcement
# Attached to every GitHub Release as fieldtest-demo.gif.
# Left pane: clawbot agent receiving hazardous instructions.
# Right pane: chainwatch guard showing real-time enforcement decisions.
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
