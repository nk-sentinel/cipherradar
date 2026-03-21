import * as vscode from "vscode";
import { getCachedFindings } from "./diagnostics";
import { getConfig } from "./config";
import { CipherRadarFinding } from "./types";

/**
 * CodeActionProvider — offers quick-fix actions on diagnostic ranges:
 *
 * 1. "Fix with CipherRadar" — calls the backend LLM remediation API and
 *    applies the suggested code change as an inline diff.
 * 2. "Suppress this finding" — inserts a `// cradar:ignore <rule-id>` comment.
 */
export class CipherRadarCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken,
  ): vscode.CodeAction[] {
    const findings = getCachedFindings(document.uri);
    if (findings.length === 0) {
      return [];
    }

    const actions: vscode.CodeAction[] = [];

    // Match diagnostics from context that belong to CipherRadar
    const crDiags = context.diagnostics.filter(
      (d) => d.source === "CipherRadar",
    );

    for (const diag of crDiags) {
      const finding = findings.find(
        (f) => f.ruleId === diag.code && rangeContains(f, diag.range),
      );

      if (!finding) {
        continue;
      }

      // Action 1: Fix with CipherRadar (LLM remediation via backend API)
      const config = getConfig();
      if (config.apiUrl) {
        const fixAction = new vscode.CodeAction(
          "Fix with CipherRadar",
          vscode.CodeActionKind.QuickFix,
        );
        fixAction.diagnostics = [diag];
        fixAction.command = {
          command: "cipherradar.applyRemediation",
          title: "Fix with CipherRadar",
          arguments: [document.uri, finding],
        };
        fixAction.isPreferred = true;
        actions.push(fixAction);
      }

      // Action 2: Suppress this finding
      const suppressAction = new vscode.CodeAction(
        `Suppress: ${finding.ruleId}`,
        vscode.CodeActionKind.QuickFix,
      );
      suppressAction.diagnostics = [diag];
      suppressAction.edit = buildSuppressEdit(document, diag.range, finding.ruleId);
      actions.push(suppressAction);
    }

    return actions;
  }
}

// ---------------------------------------------------------------------------
// Suppress edit — inserts `// cradar:ignore <rule-id>` above the finding line
// ---------------------------------------------------------------------------

function buildSuppressEdit(
  document: vscode.TextDocument,
  range: vscode.Range,
  ruleId: string,
): vscode.WorkspaceEdit {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const indent = line.text.substring(0, line.firstNonWhitespaceCharacterIndex);
  const comment = `${indent}// cradar:ignore ${ruleId}\n`;
  edit.insert(document.uri, new vscode.Position(range.start.line, 0), comment);
  return edit;
}

// ---------------------------------------------------------------------------
// LLM remediation command handler
// ---------------------------------------------------------------------------

/**
 * Register the `cipherradar.applyRemediation` command that calls the backend
 * API to get a code fix and shows an inline diff for the user to accept.
 */
export function registerRemediationCommand(
  context: vscode.ExtensionContext,
): void {
  const disposable = vscode.commands.registerCommand(
    "cipherradar.applyRemediation",
    async (uri: vscode.Uri, finding: CipherRadarFinding) => {
      const config = getConfig();
      if (!config.apiUrl) {
        vscode.window.showWarningMessage(
          "CipherRadar: configure cipherradar.apiUrl to use LLM remediation.",
        );
        return;
      }

      if (!finding.findingId) {
        vscode.window.showWarningMessage(
          "CipherRadar: this finding has no backend ID — cannot request remediation.",
        );
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "CipherRadar: requesting remediation...",
          cancellable: false,
        },
        async () => {
          try {
            const response = await fetchRemediation(
              config.apiUrl,
              config.apiKey,
              finding.findingId!,
            );

            if (!response.patch) {
              vscode.window.showInformationMessage(
                "CipherRadar: no remediation available for this finding.",
              );
              return;
            }

            // Open a diff editor so the user can review before applying
            const document = await vscode.workspace.openTextDocument(uri);
            const original = document.getText();
            const patched = applyTextPatch(original, response.patch);

            const patchedUri = vscode.Uri.parse(
              `cipherradar-patch:${uri.fsPath}?patched`,
            );

            // Show the diff
            await vscode.commands.executeCommand(
              "vscode.diff",
              uri,
              patchedUri,
              `CipherRadar Fix: ${finding.ruleId}`,
            );

            const accept = await vscode.window.showInformationMessage(
              "Apply the suggested fix?",
              "Apply",
              "Dismiss",
            );

            if (accept === "Apply") {
              const edit = new vscode.WorkspaceEdit();
              const fullRange = new vscode.Range(
                document.positionAt(0),
                document.positionAt(original.length),
              );
              edit.replace(uri, fullRange, patched);
              await vscode.workspace.applyEdit(edit);
              vscode.window.showInformationMessage("CipherRadar: fix applied.");
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            vscode.window.showErrorMessage(
              `CipherRadar remediation failed: ${msg}`,
            );
          }
        },
      );
    },
  );

  context.subscriptions.push(disposable);
}

// ---------------------------------------------------------------------------
// Backend API call
// ---------------------------------------------------------------------------

interface RemediationResponse {
  patch: string;
  explanation?: string;
}

async function fetchRemediation(
  apiUrl: string,
  apiKey: string,
  findingId: string,
): Promise<RemediationResponse> {
  const url = `${apiUrl.replace(/\/+$/, "")}/findings/${findingId}/remediate`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  // Use the built-in fetch (available in Node 18+, which VS Code 1.90+ ships)
  const resp = await fetch(url, {
    method: "POST",
    headers,
  });

  if (!resp.ok) {
    throw new Error(`API returned ${resp.status}: ${resp.statusText}`);
  }

  return (await resp.json()) as RemediationResponse;
}

// ---------------------------------------------------------------------------
// Minimal text patch applier (line-level replacement)
// ---------------------------------------------------------------------------

function applyTextPatch(original: string, patch: string): string {
  // The backend returns a full replacement text for the affected region.
  // For a real implementation this would parse a unified diff; for now we
  // treat `patch` as the complete replacement content.
  return patch || original;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function rangeContains(
  finding: CipherRadarFinding,
  diagRange: vscode.Range,
): boolean {
  return (
    finding.range.startLine === diagRange.start.line &&
    finding.range.startColumn === diagRange.start.character
  );
}
