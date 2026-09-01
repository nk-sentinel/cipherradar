// Package container implements OCI container image scanning for CipherRadar.
// It materializes image filesystem layers into a temp directory and runs the
// same detection pipeline used for directory scans (Pass 1 tree-sitter, Pass 2
// OpenGrep, Pass 3 YARA-X), so binaries and text in layers are covered just
// like a source tree.
package container

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/nk-sentinel/cipherradar/cli/internal/opengrep"
	"github.com/nk-sentinel/cipherradar/cli/internal/rules"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/yarax"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ScanImage scans an OCI container image for crypto assets. Accepts either:
//   - image reference: "nginx:latest", "gcr.io/project/image:tag"
//   - local tar: "/path/to/image.tar"
//
// Layers are materialized to a temp directory (tar-slip-safe) and scanned via
// the shared directory walker plus OpenGrep, so requested passes actually run
// on image content (gh #83). Findings are stamped with their originating layer.
func ScanImage(imageRef string, registry *scanner.Registry, passes []int) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:    imageRef,
		StartTime: time.Now(),
	}

	img, err := resolveImage(imageRef)
	if err != nil {
		return nil, fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	dir, layerOf, extractErrs, err := ExtractToDir(img)
	if err != nil {
		return nil, fmt.Errorf("extracting layers from %q: %w", imageRef, err)
	}
	defer os.RemoveAll(dir)
	result.Errors = append(result.Errors, extractErrs...)

	// Pass 1 (+ Pass 3 when requested, + the regex universal) via the shared
	// directory walker over the materialized layers. Default ignores are
	// disabled: a built image is an artifact, not a source tree, so
	// vendor/build heuristics would wrongly hide real content.
	walkRes, err := scanner.ScanDirWithOptions(dir, registry, passes, scanner.ScanOptions{
		NoDefaultIgnores: true,
		NoGitignore:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("scanning image %q contents: %w", imageRef, err)
	}
	result.Findings = append(result.Findings, walkRes.Findings...)
	result.Errors = append(result.Errors, walkRes.Errors...)
	result.FilesScanned = walkRes.FilesScanned

	// Track the passes that actually ran (honest PassesRun, gh #83). Pass 1
	// always runs via the walker; Pass 3 only ran if yr is available (the CLI
	// hard-fails earlier when Pass 3 is explicitly requested without yr, but
	// gate here too so direct callers report honestly). Pass 2 is appended
	// below when OpenGrep executes.
	var ranPasses []int
	if containsPassInt(passes, 1) {
		ranPasses = append(ranPasses, 1)
	}
	if containsPassInt(passes, 3) {
		if r := yarax.NewRunner(); r != nil && r.Available() {
			ranPasses = append(ranPasses, 3)
		}
	}

	// Pass 2 (OpenGrep) over the same directory. Best-effort: if opengrep isn't
	// installed, skip it rather than failing the whole image scan.
	if containsPassInt(passes, 2) {
		if r := opengrep.NewRunner(); r != nil {
			if rulesDir, rerr := rules.ExtractToTempDir(); rerr == nil {
				defer os.RemoveAll(rulesDir)
				p2, serr := r.Scan(dir, rulesDir)
				if serr != nil {
					result.Errors = append(result.Errors, types.ScanError{
						Message: fmt.Sprintf("container Pass 2 (opengrep): %v", serr),
					})
				} else {
					result.Findings = opengrep.DeduplicateFindings(result.Findings, p2)
					ranPasses = append(ranPasses, 2)
				}
			}
		}
	}

	stampLayerProvenance(result.Findings, dir, layerOf)
	result.PassesRun = sortedUnique(ranPasses)
	result.EndTime = time.Now()
	return result, nil
}

func containsPassInt(passes []int, p int) bool {
	for _, x := range passes {
		if x == p {
			return true
		}
	}
	return false
}

func sortedUnique(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// stampLayerProvenance marks each finding as container-layer material and, when
// its file resolves to an extracted path, appends the originating layer digest.
func stampLayerProvenance(findings []types.Finding, dir string, layerOf map[string]string) {
	dirPrefix := filepath.ToSlash(dir) + "/"
	for i := range findings {
		findings[i].Properties.MaterialType = "container-layer"
		key := filepath.ToSlash(findings[i].Location.File)
		key = strings.TrimPrefix(key, dirPrefix) // opengrep may emit absolute paths
		if d, ok := layerOf[key]; ok {
			findings[i].Description += fmt.Sprintf(" [layer: %s]", d)
		}
	}
}

// resolveImage loads the image from either a local tarball or a remote registry.
func resolveImage(imageRef string) (v1.Image, error) {
	if isLocalTar(imageRef) {
		return tarball.ImageFromPath(imageRef, nil)
	}
	return pullRemoteImage(imageRef)
}

// isLocalTar returns true if the imageRef points to a local tar file.
func isLocalTar(imageRef string) bool {
	if strings.HasSuffix(strings.ToLower(imageRef), ".tar") {
		if _, err := os.Stat(imageRef); err == nil {
			return true
		}
	}
	return false
}

// pullRemoteImage fetches an image from a remote OCI registry using the
// default keychain for authentication (anonymous for public images).
func pullRemoteImage(imageRef string) (v1.Image, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", imageRef, err)
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", imageRef, err)
	}

	return img, nil
}
