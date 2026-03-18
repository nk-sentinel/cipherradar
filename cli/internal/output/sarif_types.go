package output

// SARIFDocument is the top-level SARIF 2.1.0 envelope.
type SARIFDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool's primary component.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a single detection rule.
type SARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription *SARIFMessage          `json:"shortDescription,omitempty"`
	DefaultConfig    *SARIFRuleConfig       `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRuleConfig holds the default configuration for a rule.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage holds a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location within a source file.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation pinpoints a physical file and region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies an artifact by URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion specifies a region within a source file.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
