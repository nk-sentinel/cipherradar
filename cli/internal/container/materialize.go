package container

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

const (
	// containerMaxFileBytes caps a single extracted file. Files are streamed to
	// disk (not buffered in memory), so this bounds disk/scan cost per file, not
	// peak RAM. Generous enough for CA bundles, keystores, and most crypto
	// libraries/binaries; WS4.5 makes it configurable + type-aware.
	containerMaxFileBytes int64 = 100 << 20 // 100 MB
	// containerMaxTotalBytes bounds cumulative extraction so a huge (or
	// maliciously large) image cannot fill the disk.
	containerMaxTotalBytes int64 = 2 << 30 // 2 GB
)

// ExtractToDir materializes an image's layers into a fresh temp directory and
// returns that directory, a map of extracted relative path -> originating layer
// digest (for provenance), any non-fatal extraction errors, and a fatal error.
//
// Layers are applied in order (last-writer-wins by path). A `.wh.<name>`
// whiteout marker removes a file written by a lower layer; opaque-dir markers
// (`.wh..wh..opq`) are not applied in this pass (WS4.1 scope decision).
//
// Security: entry paths are sanitized so a crafted tar cannot escape the temp
// root (tar-slip / zip-slip). Only regular files are written — symlinks,
// hardlinks, and devices are skipped, so no symlink-target escape is possible.
// The caller owns the returned directory and must os.RemoveAll it.
//
// maxTotalBytes overrides the cumulative-extraction budget; a value <= 0 uses
// the built-in containerMaxTotalBytes default (2 GB). It bounds the total bytes
// written across all layers so a huge (or maliciously bloated) image cannot
// exhaust the disk / temp space before scanning even starts.
func ExtractToDir(img v1.Image, maxTotalBytes int64) (dir string, layerOf map[string]string, extractErrs []types.ScanError, err error) {
	if maxTotalBytes <= 0 {
		maxTotalBytes = containerMaxTotalBytes
	}
	layers, err := img.Layers()
	if err != nil {
		return "", nil, nil, fmt.Errorf("reading image layers: %w", err)
	}

	dir, err = os.MkdirTemp("", "cradar-image-*")
	if err != nil {
		return "", nil, nil, fmt.Errorf("creating extraction dir: %w", err)
	}

	layerOf = make(map[string]string)
	var total int64
	budgetHit := false

	for _, layer := range layers {
		if budgetHit {
			break
		}
		digest, derr := layer.Digest()
		layerDigest := "unknown"
		if derr == nil {
			layerDigest = digest.Hex
			if len(layerDigest) > 12 {
				layerDigest = layerDigest[:12]
			}
		}

		rc, uerr := layer.Uncompressed()
		if uerr != nil {
			extractErrs = append(extractErrs, types.ScanError{
				Message: fmt.Sprintf("uncompressing layer %s: %v", layerDigest, uerr),
			})
			continue
		}

		tr := tar.NewReader(rc)
		for {
			hdr, nerr := tr.Next()
			if nerr == io.EOF {
				break
			}
			if nerr != nil {
				extractErrs = append(extractErrs, types.ScanError{
					Message: fmt.Sprintf("reading tar entry in layer %s: %v", layerDigest, nerr),
				})
				break
			}

			rel, ok := sanitizeEntryPath(hdr.Name)
			if !ok {
				extractErrs = append(extractErrs, types.ScanError{
					File:    hdr.Name,
					Message: fmt.Sprintf("skipped unsafe tar path in layer %s", layerDigest),
				})
				continue
			}

			// Whiteout handling (last-writer-wins deletion). A `.wh.<name>`
			// entry deletes <name> in the same directory from earlier layers.
			base := filepath.Base(rel)
			if strings.HasPrefix(base, ".wh.") {
				if base == ".wh..wh..opq" {
					continue // opaque-dir markers not applied in this pass
				}
				victim := filepath.Join(dir, filepath.Dir(rel), strings.TrimPrefix(base, ".wh."))
				if within(dir, victim) {
					_ = os.RemoveAll(victim)
					delete(layerOf, relFromDir(dir, victim))
				}
				continue
			}

			// Only materialize regular files.
			if hdr.Typeflag != tar.TypeReg {
				continue
			}
			if hdr.Size > containerMaxFileBytes {
				continue
			}
			if total+hdr.Size > maxTotalBytes {
				extractErrs = append(extractErrs, types.ScanError{
					Message: fmt.Sprintf("extraction budget %d bytes exceeded; remaining layers skipped", maxTotalBytes),
				})
				budgetHit = true
				break
			}

			target := filepath.Join(dir, rel)
			if werr := writeFile(target, tr); werr != nil {
				extractErrs = append(extractErrs, types.ScanError{
					File:    hdr.Name,
					Message: fmt.Sprintf("writing %s from layer %s: %v", rel, layerDigest, werr),
				})
				continue
			}
			// Track actual bytes via stat (hdr.Size can lie; writeFile capped it).
			if info, serr := os.Stat(target); serr == nil {
				total += info.Size()
			}
			layerOf[rel] = layerDigest // last writer wins
		}
		_ = rc.Close()
	}

	return dir, layerOf, extractErrs, nil
}

// sanitizeEntryPath cleans a tar entry name to a safe relative path for the
// extraction dir. Leading slashes are stripped (image tars often use
// absolute-looking, /-rooted names), but any `..` traversal that would escape
// the root is rejected outright (ok=false) so it is skipped and logged rather
// than silently remapped. The returned rel never begins with "..", so
// filepath.Join(dir, rel) is always inside dir.
func sanitizeEntryPath(name string) (string, bool) {
	rel := path.Clean(strings.TrimLeft(filepath.ToSlash(strings.TrimSpace(name)), "/"))
	if rel == "" || rel == "." {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

// writeFile streams up to containerMaxFileBytes from r into target (creating
// parent dirs), discarding anything beyond the cap.
func writeFile(target string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	n, cerr := io.Copy(f, io.LimitReader(r, containerMaxFileBytes+1))
	closeErr := f.Close()
	if cerr != nil {
		_ = os.Remove(target)
		return cerr
	}
	if n > containerMaxFileBytes {
		_ = os.Remove(target)
		return fmt.Errorf("file exceeds %d byte cap", containerMaxFileBytes)
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

// within reports whether path is inside root (defense-in-depth for whiteout
// deletion targets).
func within(root, path string) bool {
	rp, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rp != ".." && !strings.HasPrefix(rp, ".."+string(os.PathSeparator))
}

// relFromDir returns path relative to dir using forward slashes (matching the
// keys stored in layerOf).
func relFromDir(dir, path string) string {
	rp, err := filepath.Rel(dir, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rp)
}
