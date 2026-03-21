import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import { getConfig } from "./config";
import {
  SarifLog,
  SarifResult,
  SarifLevel,
  CipherRadarFinding,
  FindingSeverity,
  FindingRange,
} from "./types";

/** Shared diagnostic collection — importable by other modules. */
export const diagnosticCollection =
  vscode.languages.createDiagnosticCollection("cipherradar");

/** In-memory cache of findings keyed by file URI string. */
const findingsCache = new Map<string, CipherRadarFinding[]>();

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/**
 * Scan a single file via the `cradar` CLI, parse SARIF output, and update
 * the VS Code diagnostic collection.
 */
export async function scanFile(
  document: vscode.TextDocument,
): Promise<CipherRadarFinding[]> {
  const config = getConfig();
  const filePath = document.uri.fsPath;

  let sarifJson: string;
  try {
    sarifJson = await runCradar(config.cradarPath, filePath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showWarningMessage(`CipherRadar scan failed: ${msg}`);
    return [];
  }

  let sarif: SarifLog;
  try {
    sarif = JSON.parse(sarifJson) as SarifLog;
  } catch {
    vscode.window.showWarningMessage(
      "CipherRadar: failed to parse SARIF output",
    );
    return [];
  }

  const findings = sarifToFindings(sarif, filePath);
  findingsCache.set(document.uri.toString(), findings);

  const minLevel = severityOrdinal(config.severityMinLevel);
  const diagnostics = findings
    .filter((f) => severityOrdinal(f.severity) <= minLevel)
    .map(findingToDiagnostic);

  diagnosticCollection.set(document.uri, diagnostics);

  return findings;
}

/**
 * Return cached findings for a file URI (or empty array).
 */
export function getCachedFindings(uri: vscode.Uri): CipherRadarFinding[] {
  return findingsCache.get(uri.toString()) ?? [];
}

/**
 * Return all cached findings across the workspace.
 */
export function getAllFindings(): Map<string, CipherRadarFinding[]> {
  return new Map(findingsCache);
}

/**
 * Clear diagnostics and cache for a specific URI or all files.
 */
export function clearDiagnostics(uri?: vscode.Uri): void {
  if (uri) {
    diagnosticCollection.delete(uri);
    findingsCache.delete(uri.toString());
  } else {
    diagnosticCollection.clear();
    findingsCache.clear();
  }
}

// -------------------------------------------------------------------------
// CLI subprocess
// -------------------------------------------------------------------------

function runCradar(binaryPath: string, filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const workspaceRoot =
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? path.dirname(filePath);

    const proc = cp.execFile(
      binaryPath,
      ["scan", "--format", "sarif", "--file", filePath],
      {
        cwd: workspaceRoot,
        maxBuffer: 10 * 1024 * 1024, // 10 MB
        timeout: 60_000, // 60 s
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(stderr || error.message));
          return;
        }
        resolve(stdout);
      },
    );

    // Ensure the child process is cleaned up if the extension deactivates
    proc.unref();
  });
}

// -------------------------------------------------------------------------
// SARIF → Finding mapping
// -------------------------------------------------------------------------

function sarifToFindings(
  sarif: SarifLog,
  defaultFile: string,
): CipherRadarFinding[] {
  const findings: CipherRadarFinding[] = [];

  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      const region = loc?.region;
      const artifactUri = loc?.artifactLocation?.uri;

      const fileUri = artifactUri
        ? vscode.Uri.file(path.resolve(defaultFile, "..", artifactUri)).toString()
        : vscode.Uri.file(defaultFile).toString();

      const range: FindingRange = {
        startLine: Math.max((region?.startLine ?? 1) - 1, 0),
        startColumn: Math.max((region?.startColumn ?? 1) - 1, 0),
        endLine: Math.max((region?.endLine ?? region?.startLine ?? 1) - 1, 0),
        endColumn: Math.max((region?.endColumn ?? 200) - 1, 0),
      };

      const props = result.properties ?? {};

      findings.push({
        ruleId: result.ruleId,
        message: result.message.text,
        severity: mapSarifLevel(result.level, props.quantumStatus as string | undefined),
        fileUri,
        range,
        algorithmName: props.algorithmName as string | undefined,
        algorithmFamily: props.algorithmFamily as string | undefined,
        quantumStatus: props.quantumStatus as CipherRadarFinding["quantumStatus"],
        pqcReplacement: props.pqcReplacement as string | undefined,
        complianceTags: props.complianceTags as string[] | undefined,
        findingId: props.findingId as string | undefined,
        remediationHint: props.remediationHint as string | undefined,
      });
    }
  }

  return findings;
}

/**
 * Map SARIF level + quantum status to VS Code diagnostic severity.
 *
 * Per ADR-029:
 * - Deprecated algorithm (MD5, DES, etc.) → Error
 * - Quantum-vulnerable → Warning
 * - Quantum-safe / informational → Information
 */
function mapSarifLevel(
  level: SarifLevel | undefined,
  quantumStatus: string | undefined,
): FindingSeverity {
  if (level === "error") {
    return "error";
  }
  if (level === "warning" || quantumStatus === "vulnerable") {
    return "warning";
  }
  if (level === "note" || level === "none") {
    return "information";
  }
  return "information";
}

// -------------------------------------------------------------------------
// Finding → Diagnostic
// -------------------------------------------------------------------------

function findingToDiagnostic(finding: CipherRadarFinding): vscode.Diagnostic {
  const range = new vscode.Range(
    finding.range.startLine,
    finding.range.startColumn,
    finding.range.endLine,
    finding.range.endColumn,
  );

  const severity = vscSeverity(finding.severity);

  const diag = new vscode.Diagnostic(range, finding.message, severity);
  diag.source = "CipherRadar";
  diag.code = finding.ruleId;

  return diag;
}

function vscSeverity(
  s: FindingSeverity,
): vscode.DiagnosticSeverity {
  switch (s) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    case "hint":
      return vscode.DiagnosticSeverity.Hint;
  }
}

function severityOrdinal(s: FindingSeverity): number {
  switch (s) {
    case "error":
      return 0;
    case "warning":
      return 1;
    case "information":
      return 2;
    case "hint":
      return 3;
  }
}
