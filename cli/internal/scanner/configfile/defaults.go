package configfile

import (
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// RegisterAll registers all configfile scanners with the given registry.
func RegisterAll(registry *scanner.Registry) {
	// .conf files are handled by a multiplexer that dispatches to the
	// appropriate scanner (nginx or httpd) based on content heuristics.
	registry.Register(&confMultiplexer{
		nginx: NewNginx(),
		httpd: NewHttpd(),
	})

	// .cnf files (OpenSSL config).
	registry.Register(NewOpenSSLCnf())

	// .security files (Java security properties).
	registry.Register(NewJavaSecurity())

	// .yaml/.yml files (Kubernetes manifests).
	registry.Register(NewKubernetes())

	// Dockerfiles have no extension; registered as universal scanner
	// with internal filename-based filtering.
	registry.RegisterUniversal(NewDockerfile())
}

// confMultiplexer dispatches .conf files to either nginx or httpd scanner
// based on content heuristics. Both scanners are tried since a file might
// match neither (generic .conf files are silently skipped).
type confMultiplexer struct {
	nginx *NginxScanner
	httpd *HttpdScanner
}

func (m *confMultiplexer) Name() string            { return "conf-multiplexer" }
func (m *confMultiplexer) Extensions() []string     { return []string{".conf"} }

func (m *confMultiplexer) ScanFile(path string, content []byte) ([]types.Finding, error) {
	var allFindings []types.Finding

	// Try nginx scanner.
	findings, err := m.nginx.ScanFile(path, content)
	if err != nil {
		return nil, err
	}
	allFindings = append(allFindings, findings...)

	// Try httpd scanner (will skip if content doesn't match Apache heuristics).
	findings, err = m.httpd.ScanFile(path, content)
	if err != nil {
		return nil, err
	}
	allFindings = append(allFindings, findings...)

	return allFindings, nil
}
