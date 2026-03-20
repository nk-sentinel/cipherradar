// Package container implements OCI container image scanning for CipherRadar.
// It extracts filesystem layers from container images and dispatches files to
// the scanner registry for cryptographic asset detection.
package container

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

const (
	// maxFileSize is the maximum size of a file to scan within a layer (1 MB).
	maxFileSize = 1 << 20
	// maxLayerSize is the maximum uncompressed layer size to process (500 MB).
	maxLayerSize = 500 << 20
)

// layerFile represents a file extracted from a container image layer.
type layerFile struct {
	path        string // path within the image filesystem
	content     []byte
	layerDigest string // truncated SHA of the layer
}

// scanJob represents a file to be scanned by the worker pool.
type scanJob struct {
	file     layerFile
	scanner  scanner.Scanner
	universals []scanner.Scanner
}

// scanJobResult holds the output from scanning a single file.
type scanJobResult struct {
	findings []types.Finding
	errors   []types.ScanError
	scanned  bool
}

// ScanImage scans an OCI container image for crypto assets.
// Accepts either:
//   - image reference: "nginx:latest", "gcr.io/project/image:tag"
//   - local tar: "/path/to/image.tar"
func ScanImage(imageRef string, registry *scanner.Registry, passes []int) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:    imageRef,
		StartTime: time.Now(),
		PassesRun: passes,
	}

	img, err := resolveImage(imageRef)
	if err != nil {
		return nil, fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	files, extractErrors, err := extractLayers(img)
	if err != nil {
		return nil, fmt.Errorf("extracting layers from %q: %w", imageRef, err)
	}
	result.Errors = append(result.Errors, extractErrors...)

	if len(files) == 0 {
		result.EndTime = time.Now()
		return result, nil
	}

	// Build scan jobs.
	var jobs []scanJob
	for _, f := range files {
		ext := scanner.DetectLanguage(f.path)
		s := registry.ForExtension(ext)
		universals := registry.Universals()

		if s == nil && len(universals) == 0 {
			continue
		}

		job := scanJob{
			file:    f,
			scanner: s,
		}
		if s == nil {
			job.universals = universals
		}
		jobs = append(jobs, job)
	}

	// Process jobs concurrently.
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	results := make([]scanJobResult, len(jobs))

	var wg sync.WaitGroup
	jobCh := make(chan int, len(jobs))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				job := jobs[idx]
				var findings []types.Finding
				var errs []types.ScanError
				scanned := false

				if job.scanner != nil {
					f, scanErr := job.scanner.ScanFile(job.file.path, job.file.content)
					if scanErr != nil {
						errs = append(errs, types.ScanError{
							File:    job.file.path,
							Message: scanErr.Error(),
						})
					} else {
						findings = append(findings, f...)
					}
					scanned = true
				}

				if job.scanner == nil {
					for _, us := range job.universals {
						f, scanErr := us.ScanFile(job.file.path, job.file.content)
						if scanErr != nil {
							errs = append(errs, types.ScanError{
								File:    job.file.path,
								Message: scanErr.Error(),
							})
							continue
						}
						findings = append(findings, f...)
						scanned = true
					}
				}

				// Attribute each finding to the container layer.
				for i := range findings {
					findings[i].Properties.MaterialType = "container-layer"
					findings[i].Description += fmt.Sprintf(" [layer: %s]", job.file.layerDigest)
				}

				results[idx] = scanJobResult{
					findings: findings,
					errors:   errs,
					scanned:  scanned,
				}
			}
		}()
	}

	for i := range jobs {
		jobCh <- i
	}
	close(jobCh)
	wg.Wait()

	// Collect results.
	filesScanned := 0
	for _, r := range results {
		result.Findings = append(result.Findings, r.findings...)
		result.Errors = append(result.Errors, r.errors...)
		if r.scanned {
			filesScanned++
		}
	}
	result.FilesScanned = filesScanned

	// Sort findings for deterministic output.
	sort.Slice(result.Findings, func(i, j int) bool {
		fi, fj := result.Findings[i], result.Findings[j]
		if fi.Location.File != fj.Location.File {
			return fi.Location.File < fj.Location.File
		}
		return fi.Location.StartLine < fj.Location.StartLine
	})

	// Assign sequential finding IDs.
	for i := range result.Findings {
		result.Findings[i].ID = fmt.Sprintf("FIND-%d", i+1)
	}

	result.EndTime = time.Now()
	return result, nil
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

// extractLayers iterates over all image layers and extracts scannable files.
// Returns the collected files, any non-fatal extraction errors, and any fatal error.
func extractLayers(img v1.Image) ([]layerFile, []types.ScanError, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, nil, fmt.Errorf("getting layers: %w", err)
	}

	var files []layerFile
	var extractErrors []types.ScanError

	for _, layer := range layers {
		digest, err := layer.DiffID()
		if err != nil {
			extractErrors = append(extractErrors, types.ScanError{
				Message: fmt.Sprintf("getting layer diff ID: %v", err),
			})
			continue
		}

		layerDigest := digest.Hex
		if len(layerDigest) > 12 {
			layerDigest = layerDigest[:12]
		}

		// Check uncompressed layer size.
		size, err := layer.Size()
		if err == nil && size > maxLayerSize {
			extractErrors = append(extractErrors, types.ScanError{
				Message: fmt.Sprintf("skipping layer %s: size %d exceeds limit %d", layerDigest, size, maxLayerSize),
			})
			continue
		}

		layerFiles, layerErrors := extractLayer(layer, layerDigest)
		files = append(files, layerFiles...)
		extractErrors = append(extractErrors, layerErrors...)
	}

	return files, extractErrors, nil
}

// extractLayer reads the tar stream of a single layer and returns scannable files.
func extractLayer(layer v1.Layer, layerDigest string) ([]layerFile, []types.ScanError) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, []types.ScanError{{
			Message: fmt.Sprintf("uncompressing layer %s: %v", layerDigest, err),
		}}
	}
	defer rc.Close()

	var files []layerFile
	var errors []types.ScanError

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			errors = append(errors, types.ScanError{
				Message: fmt.Sprintf("reading tar entry in layer %s: %v", layerDigest, err),
			})
			break
		}

		// Skip directories, symlinks, and non-regular files.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Skip whiteout files (OCI layer deletion markers).
		base := filepath.Base(hdr.Name)
		if strings.HasPrefix(base, ".wh.") {
			continue
		}

		// Skip files exceeding size limit.
		if hdr.Size > maxFileSize {
			continue
		}

		// Skip binary file extensions.
		if isBinaryExtension(hdr.Name) {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(tr, maxFileSize+1))
		if err != nil {
			errors = append(errors, types.ScanError{
				File:    hdr.Name,
				Message: fmt.Sprintf("reading file in layer %s: %v", layerDigest, err),
			})
			continue
		}
		if int64(len(content)) > maxFileSize {
			continue
		}

		// Skip files that appear to be binary (contain null bytes in first 512 bytes).
		if isBinaryContent(content) {
			continue
		}

		files = append(files, layerFile{
			path:        hdr.Name,
			content:     content,
			layerDigest: layerDigest,
		})
	}

	return files, errors
}

// isBinaryExtension returns true for common binary file extensions that should
// be skipped during scanning.
func isBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj",
		".pyc", ".pyo", ".class",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".zst",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
		".mp3", ".mp4", ".avi", ".mov", ".wav",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".bin", ".dat":
		return true
	}
	return false
}

// isBinaryContent checks if content appears to be binary by looking for null
// bytes in the first 512 bytes.
func isBinaryContent(content []byte) bool {
	probe := content
	if len(probe) > 512 {
		probe = probe[:512]
	}
	for _, b := range probe {
		if b == 0 {
			return true
		}
	}
	return false
}
