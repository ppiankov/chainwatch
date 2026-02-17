package policy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzLoadConfigYAML(f *testing.F) {
	// Seed with valid default config YAML
	f.Add([]byte(DefaultConfigYAML()))

	// Seed with minimal valid YAML
	f.Add([]byte(`thresholds:
  allow_max: 5
  approval_min: 11
`))

	// Seed with empty
	f.Add([]byte{})

	// Seed with garbage
	f.Add([]byte(`{{{not yaml at all`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input
		var cfg PolicyConfig
		yaml.Unmarshal(data, &cfg)
	})
}
