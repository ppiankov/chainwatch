package profile

import _ "embed"

//go:embed profiles/clawbot.yaml
var clawbotYAML []byte

//go:embed profiles/coding-agent.yaml
var codingAgentYAML []byte

//go:embed profiles/research-agent.yaml
var researchAgentYAML []byte

//go:embed profiles/customer-support.yaml
var customerSupportYAML []byte

//go:embed profiles/data-analyst.yaml
var dataAnalystYAML []byte

//go:embed profiles/vm-cloud.yaml
var vmCloudYAML []byte

// builtinProfiles maps profile names to their embedded YAML content.
var builtinProfiles = map[string][]byte{
	"clawbot":          clawbotYAML,
	"coding-agent":     codingAgentYAML,
	"research-agent":   researchAgentYAML,
	"customer-support": customerSupportYAML,
	"data-analyst":     dataAnalystYAML,
	"vm-cloud":         vmCloudYAML,
}
