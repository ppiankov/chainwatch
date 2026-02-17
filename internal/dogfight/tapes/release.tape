# Chainwatch Release Dogfight — Split-Screen Proof of Enforcement
# Attached to every GitHub Release as dogfight-demo.gif.
# Left pane: clawbot agent receiving hazardous instructions.
# Right pane: chainwatch guard showing real-time enforcement decisions.
# Run: vhs internal/dogfight/tapes/release.tape

Output dogfight-demo.gif

Set Shell "bash"
Set Width 1400
Set Height 900
Set Theme "Dracula"
Set FontSize 13
Set Padding 10

Type "bash internal/dogfight/scripts/release-demo.sh"
Enter
Sleep 55s
