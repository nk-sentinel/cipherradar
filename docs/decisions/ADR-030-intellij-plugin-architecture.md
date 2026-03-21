# ADR-030: IntelliJ Plugin Architecture — External Annotator

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

IntelliJ IDEA (and JetBrains IDEs based on the IntelliJ Platform) is the dominant IDE for Java and Kotlin development and widely used for Python (PyCharm), Go (GoLand), and JavaScript/TypeScript (WebStorm). Enterprise Java shops — a primary CipherRadar target audience — overwhelmingly use IntelliJ-based IDEs.

The IntelliJ Platform provides a rich annotation and inspection framework. The plugin must integrate with the platform's threading model (EDT for UI, background threads for computation) and present findings using native IntelliJ UI patterns: annotations with gutter icons, tooltips, quick-fix intentions, and tool windows.

---

## Decision

### External Annotator pattern

The plugin uses IntelliJ's `ExternalAnnotator<CollectedInfo, AnnotationResult>` API, which is designed for integrating external analysis tools. This pattern correctly separates work across the platform's threading model:

**Phase 1: `collectInformation()` (EDT thread)**
Reads the file path and current editor state. Runs on the Event Dispatch Thread — must be fast and non-blocking. Returns a lightweight `CollectedInfo` object containing only the file path and document modification stamp.

**Phase 2: `doAnnotate()` (background thread)**
Runs on a background thread (not EDT). Reads cached CBOM/SARIF output from the most recent `cradar scan` of the project. If no cached results exist or the file has been modified since the last scan, invokes `cradar scan --format sarif --file <path>` as a subprocess and caches the result. Parses SARIF into an `AnnotationResult` containing finding locations, severities, and metadata.

**Phase 3: `apply()` (EDT thread)**
Runs on the EDT. Creates `Annotation` objects from the `AnnotationResult`:
- Gutter icons indicating finding severity (error/warning/info)
- Tooltip text showing algorithm name, quantum status, and compliance information
- Underline highlighting on the code range containing the cryptographic call

### Quick-fix intentions

Each annotation registers `IntentionAction` implementations:

| Intention | Action |
|---|---|
| "Fix with CipherRadar" | Calls backend LLM remediation API (ADR-027); applies suggested code change via `WriteCommandAction` |
| "Suppress this finding" | Inserts `// cradar:ignore <rule-id>` comment above the finding line |
| "View in CipherRadar dashboard" | Opens the finding URL in the default browser |

### Tool window

A dedicated tool window (`ToolWindowFactory`) displays all findings in the current project, presented as a tree: severity → file → finding. Double-click navigates to the finding location. Toolbar actions: re-scan project, filter by severity, filter by quantum status.

### CLI invocation

The plugin calls `cradar` as a subprocess using `GeneralCommandLine` + `OSProcessHandler`. Binary discovery follows the same resolution order as the CLI itself: configured path in plugin settings → `$CRADAR_TOOLS_DIR` → `$PATH`.

### Configuration

Plugin settings (IntelliJ `Configurable` panel under Settings → Tools → CipherRadar):

- `cradar` binary path (auto-detected from `$PATH` if not set)
- Backend API endpoint (for LLM remediation)
- API key
- Scan on save (enabled/disabled)
- Minimum severity to display

---

## Options Considered

### Option A: Local Inspection (rejected)
IntelliJ's `LocalInspectionTool` runs PSI-level analysis within the IDE's own parsing infrastructure. Rejected because CipherRadar's detection logic lives in the `cradar` CLI binary — reimplementing it in Kotlin/JVM would duplicate the detection engine and create version drift. `ExternalAnnotator` is the platform's intended pattern for integrating external tools.

### Option B: LSP via lsp4intellij (rejected)
Using the Language Server Protocol via the `lsp4intellij` library. Rejected for the same reasons as in ADR-029: CipherRadar is not a language server and does not provide completions, references, or rename support. The LSP bridge adds protocol overhead and limits access to IntelliJ-specific UI features (gutter icons, intention actions, tool windows) that the native `ExternalAnnotator` API provides directly.

### Option C: File Watcher + Problem View only (rejected)
A minimal integration that runs `cradar` via a file watcher and populates the Problems view. Rejected because it misses the richer UX opportunities: inline annotations, gutter icons, quick-fix intentions, and the dedicated tool window. The `ExternalAnnotator` pattern provides all of these with correct threading behaviour.

---

## Consequences

- **Positive:** Native IntelliJ UX — gutter icons, tooltips, and intentions follow platform conventions
- **Positive:** Correct threading model — no EDT blocking during CLI execution
- **Positive:** SARIF caching avoids redundant scans for unchanged files
- **Positive:** Quick-fix intentions provide one-click remediation flow
- **Negative:** Plugin depends on `cradar` CLI being installed on the developer's machine
- **Negative:** Kotlin plugin requires JetBrains plugin SDK — separate build and release pipeline
- **Negative:** Must support multiple IntelliJ Platform versions (annual major releases) — compatibility matrix

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/08-roadmap.md` | Phase 4: IntelliJ plugin listed as deliverable |
| `docs/07-tech-stack.md` | IntelliJ Platform SDK, Kotlin added for IDE tooling |
