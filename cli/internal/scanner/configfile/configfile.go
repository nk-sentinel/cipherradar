// Package configfile provides scanners for infrastructure configuration files
// that contain cryptographic settings: nginx.conf, httpd.conf, openssl.cnf,
// java.security, Kubernetes manifests, and Dockerfiles.
package configfile

import (
	"fmt"
	"sync/atomic"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// findingCounter is a global atomic counter for generating unique finding IDs.
var findingCounter atomic.Int64

func nextID() string {
	n := findingCounter.Add(1)
	return fmt.Sprintf("CFGF-%04d", n)
}

// weakCiphers is the set of cipher strings considered weak or broken.
var weakCiphers = map[string]bool{
	"RC4":          true,
	"RC4-SHA":      true,
	"RC4-MD5":      true,
	"DES":          true,
	"DES-CBC-SHA":  true,
	"DES-CBC3-SHA": true,
	"3DES":         true,
	"NULL":         true,
	"NULL-SHA":     true,
	"NULL-MD5":     true,
	"EXP":          true,
	"EXPORT":       true,
	"EXPORT40":     true,
	"EXPORT56":     true,
	"aNULL":        true,
	"eNULL":        true,
	"SEED":         true,
	"IDEA":         true,
	"MD5":          true,
}

// makeFinding creates a finding with common defaults for config file scanning.
func makeFinding(
	assetType types.AssetType,
	name string,
	path string,
	line int,
	snippet string,
	severity types.Severity,
	description string,
	ruleID string,
	props types.CryptoProperties,
) types.Finding {
	return types.Finding{
		ID:          nextID(),
		AssetType:   assetType,
		Name:        name,
		Location:    types.Location{File: path, StartLine: line, StartCol: 1, EndLine: line, EndCol: len(snippet), Snippet: snippet},
		Severity:    severity,
		Confidence:  types.ConfidenceMedium,
		Properties:  props,
		Description: description,
		RuleID:      ruleID,
		Pass:        1,
	}
}
