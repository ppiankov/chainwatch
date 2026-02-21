package observe

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed runbooks/*.yaml
var builtinFS embed.FS

// loadBuiltinRunbook loads a runbook from the embedded filesystem by type name.
func loadBuiltinRunbook(name string) (*Runbook, error) {
	path := "runbooks/" + name + ".yaml"
	data, err := builtinFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("built-in runbook %q not found", name)
	}
	rb, err := ParseRunbook(data)
	if err != nil {
		return nil, fmt.Errorf("built-in runbook %s: %w", name, err)
	}
	rb.Source = "built-in"
	return rb, nil
}

// listBuiltinRunbooks returns all embedded runbooks.
func listBuiltinRunbooks() []*Runbook {
	entries, err := builtinFS.ReadDir("runbooks")
	if err != nil {
		return nil
	}
	var runbooks []*Runbook
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := builtinFS.ReadFile("runbooks/" + e.Name())
		if err != nil {
			continue
		}
		rb, err := ParseRunbook(data)
		if err != nil {
			continue
		}
		rb.Source = "built-in"
		runbooks = append(runbooks, rb)
	}
	return runbooks
}
