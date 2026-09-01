# ADR-042: Container image scanning — materialize layers, reuse the directory walker

**Status:** Accepted (2026-09-01)

## Context

`cradar scan --container <image>` is supposed to scan an OCI image with the same
depth as a directory scan. The original implementation (`internal/container`)
was a **diverged copy** of the directory walker that had drifted badly from it:

- it **pre-filtered every binary** by extension *and* a NUL-byte probe, then
- capped files at **1 MB**, and
- held file content in memory as `[]byte` with **no on-disk path**, so the
  YARA-X (`yr`) subprocess — which scans files by path — could never run, and
- it **never invoked Pass 2** (OpenGrep), attached universals only when no
  language scanner matched, and **never pass-gated** them, while
- reporting `PassesRun = passes` verbatim regardless of what actually ran.

Net effect: `--container --deep` scanned **text files ≤ 1 MB only**. Compiled
binaries — the whole reason Pass 3 exists — were scanned by neither the
byte-pattern scanner nor YARA-X, and the CBOM dishonestly claimed all requested
passes ran (gh #83). The divergence also meant every walker improvement had to
be re-implemented twice.

## Decision

**Materialize image layers to a temp directory, then run the existing directory
walker (`scanner.ScanDirWithOptions`) over that directory.** Concretely:

1. **Extract all layers to disk** (`container.ExtractToDir`) with correct
   last-writer-wins semantics and `.wh.` whiteout handling, tar-slip/zip-slip
   path sanitization (reject `..` traversal, strip leading `/`, regular files
   only — no symlink/hardlink/device targets), and a bounded per-file
   (`containerMaxFileBytes`) and cumulative (`containerMaxTotalBytes`, overridable
   via `--max-image-size`, ADR-follows the coverage-knob pattern) budget.
2. **Run the shared walker** over the extracted tree with default-ignores
   disabled (a built image is an artifact, not a source tree). This yields
   Pass 1 + Pass 3 (pass-gated YARA-X universal) + the regex universal + the
   native binary / JAR / wheel scanners **for free**. Pass 2 (OpenGrep) runs
   over the same directory via its own runner.
3. **Stamp layer provenance** on every finding (`container-layer` /
   `container-image-metadata` material type + `[layer: <digest>]` in the
   description) so a finding is traceable to the layer it came from.
4. **Ingest image config/history/labels** as synthetic files under a metadata
   subdir so crypto material that lives in metadata (a key in `ENV`, a cipher in
   build history) is covered — coverage no filesystem walker provides.
5. **Report `PassesRun` honestly** — the passes that actually executed, with
   Pass 2/3 gated on tool availability.
6. **Delete the temp directory** via `defer os.RemoveAll`.

This is how mature tools work (Syft/stereoscope, Trivy build a filesystem view of
the image, then scan it), and `yr` requires on-disk paths regardless, so
materialization is required, not incidental.

## Rejected alternatives

- **Keep the diverged in-memory copy and just add passes.** Rejected: it still
  can't feed `yr` (no paths), duplicates the walker forever, and the binary
  pre-filter defeats Pass 3's purpose.
- **Stream each layer's tar to `yr` via stdin.** Rejected: `yr` scans by path
  and per-file attribution would be lost; nested-archive routing and the native
  scanners also need real files.
- **Mount the image (overlay/squashfs) instead of copying.** Rejected: needs
  elevated privileges / FUSE, is OS-specific, and conflicts with ADR-003 (no
  special environment required); a temp-dir copy is portable and bounded.

## Consequences

- `--container` scans now match directory scans: all three passes, universals,
  pass-gating, native binary/JAR/wheel scanners, and recursive archive unpacking
  (ADR-follows binary/archive work) all apply to image content.
- Disk usage is bounded by `--max-image-size` (default 2 GB) and cleaned up after
  each scan; the diverged `container/scanner.go` scan loop is deleted.
- Findings carry per-layer provenance; copied-then-deleted material in lower
  layers and metadata-only material (ENV/history/labels) are now surfaced.
- Downstream consumers (gauntlet, ADR-025) receive real container CBOMs.
- Shipped in **v0.5.0-rc.1** (gh #83).

## Related

ADR-004 (3-pass detection), ADR-026 (binary scanning architecture),
ADR-039 (YARA-X Pass 3), ADR-003 (no build / special environment required),
ADR-025 (CLI-to-portal push).
