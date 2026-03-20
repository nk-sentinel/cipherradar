package configfile

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
)

func TestRegisterAll(t *testing.T) {
	registry := scanner.NewRegistry()
	RegisterAll(registry)

	// Should have scanners registered for these extensions.
	extensions := []string{".conf", ".cnf", ".security", ".yaml", ".yml"}
	for _, ext := range extensions {
		s := registry.ForExtension(ext)
		if s == nil {
			t.Errorf("expected scanner registered for %q, got nil", ext)
		}
	}

	// Should have at least one universal scanner (Dockerfile).
	universals := registry.Universals()
	if len(universals) == 0 {
		t.Error("expected at least one universal scanner (Dockerfile)")
	}

	foundDockerfile := false
	for _, u := range universals {
		if u.Name() == "dockerfile" {
			foundDockerfile = true
		}
	}
	if !foundDockerfile {
		t.Error("expected Dockerfile universal scanner to be registered")
	}
}

func TestConfMultiplexerName(t *testing.T) {
	m := &confMultiplexer{
		nginx: NewNginx(),
		httpd: NewHttpd(),
	}
	if m.Name() != "conf-multiplexer" {
		t.Errorf("expected name 'conf-multiplexer', got %q", m.Name())
	}
}

func TestConfMultiplexerExtensions(t *testing.T) {
	m := &confMultiplexer{
		nginx: NewNginx(),
		httpd: NewHttpd(),
	}
	exts := m.Extensions()
	if len(exts) != 1 || exts[0] != ".conf" {
		t.Errorf("expected [.conf], got %v", exts)
	}
}

func TestConfMultiplexerNginx(t *testing.T) {
	m := &confMultiplexer{
		nginx: NewNginx(),
		httpd: NewHttpd(),
	}

	content := []byte(`server {
    listen 443 ssl;
    ssl_protocols TLSv1;
}
`)
	findings, err := m.ScanFile("test.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings for nginx config")
	}
}

func TestConfMultiplexerHttpd(t *testing.T) {
	m := &confMultiplexer{
		nginx: NewNginx(),
		httpd: NewHttpd(),
	}

	content := []byte(`<VirtualHost *:443>
    SSLEngine on
    SSLProtocol +SSLv3
</VirtualHost>
`)
	findings, err := m.ScanFile("test.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings for httpd config")
	}
}

func TestConfMultiplexerGenericConf(t *testing.T) {
	m := &confMultiplexer{
		nginx: NewNginx(),
		httpd: NewHttpd(),
	}

	content := []byte(`
[section]
key = value
other = something
`)
	findings, err := m.ScanFile("generic.conf", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for generic .conf, got %d", len(findings))
	}
}
