package container

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/nk-sentinel/cipherradar/cli/internal/scannerinit"
)

// TestScanImage_IngestsEnvMetadata proves a secret baked into the image's
// environment (not the filesystem) is detected and attributed to image
// metadata (gh #83 / WS4.4).
func TestScanImage_IngestsEnvMetadata(t *testing.T) {
	// A single trivial filesystem file, plus a hardcoded secret in Config.Env.
	img := imageFromLayers(t, buildTar(t, tarEntry{"app/readme.txt", []byte("hi")}))
	img, err := mutate.Config(img, v1.Config{
		Env: []string{
			"PATH=/usr/local/bin:/usr/bin",
			"DB_PASSWORD=supersecret123",
			"API_SECRET_KEY=abcdef0123456789abcdef0123456789",
		},
	})
	if err != nil {
		t.Fatalf("mutate.Config: %v", err)
	}

	tarPath := filepath.Join(t.TempDir(), "meta-image.tar")
	tag, _ := name.NewTag("test/meta:latest")
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("write image: %v", err)
	}

	result, err := ScanImage(tarPath, scannerinit.DefaultRegistry(), []int{1})
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}

	var metaFinding bool
	for _, f := range result.Findings {
		if f.Properties.MaterialType == "container-image-metadata" ||
			strings.Contains(f.Description, "[origin: image-metadata]") {
			metaFinding = true
		}
	}
	if !metaFinding {
		t.Errorf("expected a finding attributed to image metadata (from the env secret); findings=%d", len(result.Findings))
	}
}
