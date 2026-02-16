package scenario

// ScenarioAction defines the action under test.
type ScenarioAction struct {
	Tool      string `yaml:"tool"`
	Resource  string `yaml:"resource"`
	Operation string `yaml:"operation,omitempty"`
}

// Case is one test case within a scenario.
type Case struct {
	Action  ScenarioAction `yaml:"action"`
	Expect  string         `yaml:"expect"`
	Purpose string         `yaml:"purpose,omitempty"`
	Agent   string         `yaml:"agent,omitempty"`
}

// Scenario is a named collection of policy test cases.
type Scenario struct {
	Name    string `yaml:"name"`
	Profile string `yaml:"profile,omitempty"`
	Cases   []Case `yaml:"cases"`
}

// CaseResult is the outcome of evaluating one test case.
type CaseResult struct {
	Index    int    `json:"index"`
	Passed   bool   `json:"passed"`
	Tool     string `json:"tool"`
	Resource string `json:"resource"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Reason   string `json:"reason"`
}

// RunResult is the outcome of running all cases in one scenario file.
type RunResult struct {
	File   string       `json:"file"`
	Name   string       `json:"name"`
	Total  int          `json:"total"`
	Passed int          `json:"passed"`
	Failed int          `json:"failed"`
	Cases  []CaseResult `json:"cases"`
}
