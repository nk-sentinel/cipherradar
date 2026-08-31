package container

import (
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// imageMetaSubdir is the synthetic directory (under the extraction root) where
// image config/history/labels are written so the normal walker + regex/config
// scanners inspect them like any file. Findings under it are marked as
// image-metadata rather than a filesystem layer.
const imageMetaSubdir = ".cradar-image-metadata"

// writeImageMetadata renders the image's config — environment, build history,
// labels, entrypoint/cmd — into synthetic files under dir/imageMetaSubdir so the
// scan pipeline can find crypto-relevant material that lives in metadata, not
// the filesystem: a key baked in via ENV/ARG, a TLS/cipher env setting, or a
// secret copied-then-deleted but still recorded in the layer history
// (recoverable with `docker history`). Best-effort — a missing or unreadable
// config is not fatal.
func writeImageMetadata(img v1.Image, dir string) {
	cfg, err := img.ConfigFile()
	if err != nil || cfg == nil {
		return
	}
	metaDir := filepath.Join(dir, imageMetaSubdir)
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		return
	}

	write := func(name string, lines []string) {
		if len(lines) == 0 {
			return
		}
		_ = os.WriteFile(filepath.Join(metaDir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}

	// Env as a .env file: the config scanner flags hardcoded secrets and the
	// regex universal catches embedded keys/certs and crypto env settings.
	write("environment.env", cfg.Config.Env)

	// Build history — Dockerfile RUN/COPY/ENV/ARG commands. Copied-then-deleted
	// secrets persist here even when absent from the final filesystem.
	var hist []string
	for _, h := range cfg.History {
		if s := strings.TrimSpace(h.CreatedBy); s != "" {
			hist = append(hist, s)
		}
	}
	write("history.txt", hist)

	// Labels + entrypoint/cmd.
	var meta []string
	for k, v := range cfg.Config.Labels {
		meta = append(meta, k+"="+v)
	}
	meta = append(meta, cfg.Config.Entrypoint...)
	meta = append(meta, cfg.Config.Cmd...)
	write("labels.txt", meta)
}
