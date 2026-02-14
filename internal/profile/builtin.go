package profile

import _ "embed"

//go:embed profiles/clawbot.yaml
var clawbotYAML []byte

// builtinProfiles maps profile names to their embedded YAML content.
var builtinProfiles = map[string][]byte{
	"clawbot": clawbotYAML,
}
