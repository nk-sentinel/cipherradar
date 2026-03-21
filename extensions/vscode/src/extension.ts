import * as vscode from "vscode";
import { getConfig, onConfigChange } from "./config";
import {
  diagnosticCollection,
  scanFile,
  clearDiagnostics,
} from "./diagnostics";
import { CipherRadarHoverProvider } from "./hover";
import {
  CipherRadarCodeActionProvider,
  registerRemediationCommand,
} from "./codeActions";
import { FindingsTreeProvider } from "./treeView";
import { createStatusBar, setScanning, setIdle, setError } from "./statusBar";

// ---------------------------------------------------------------------------
// Extension lifecycle
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
  // Status bar
  createStatusBar(context);

  // Tree view
  const treeProvider = new FindingsTreeProvider();
  vscode.window.registerTreeDataProvider("cipherradar.findings", treeProvider);

  // Hover provider — all file types
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      { scheme: "file" },
      new CipherRadarHoverProvider(),
    ),
  );

  // Code action provider — all file types
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new CipherRadarCodeActionProvider(),
      {
        providedCodeActionKinds:
          CipherRadarCodeActionProvider.providedCodeActionKinds,
      },
    ),
  );

  // Register the LLM remediation command
  registerRemediationCommand(context);

  // -----------------------------------------------------------------------
  // Commands
  // -----------------------------------------------------------------------

  // Manual scan current file
  context.subscriptions.push(
    vscode.commands.registerCommand("cipherradar.scan", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("CipherRadar: no active file to scan.");
        return;
      }
      await runScan(editor.document, treeProvider);
    }),
  );

  // Scan entire workspace
  context.subscriptions.push(
    vscode.commands.registerCommand("cipherradar.scanWorkspace", async () => {
      const files = await vscode.workspace.findFiles("**/*", "**/node_modules/**");
      for (const file of files) {
        try {
          const doc = await vscode.workspace.openTextDocument(file);
          await runScan(doc, treeProvider);
        } catch {
          // skip files that cannot be opened as text
        }
      }
    }),
  );

  // Clear diagnostics
  context.subscriptions.push(
    vscode.commands.registerCommand("cipherradar.clearDiagnostics", () => {
      clearDiagnostics();
      treeProvider.refresh();
      setIdle();
    }),
  );

  // -----------------------------------------------------------------------
  // Auto-scan on save
  // -----------------------------------------------------------------------

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      const config = getConfig();
      if (!config.autoScan) {
        return;
      }
      await runScan(document, treeProvider);
    }),
  );

  // -----------------------------------------------------------------------
  // Config change listener
  // -----------------------------------------------------------------------

  context.subscriptions.push(onConfigChange(() => {
    // Config changed — tree might need a refresh (e.g., severity filter)
    treeProvider.refresh();
    setIdle();
  }));

  // Keep the diagnostic collection disposable
  context.subscriptions.push(diagnosticCollection);
}

export function deactivate(): void {
  // Nothing to clean up — disposables are managed via context.subscriptions
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function runScan(
  document: vscode.TextDocument,
  treeProvider: FindingsTreeProvider,
): Promise<void> {
  setScanning();
  try {
    await scanFile(document);
    treeProvider.refresh();
    setIdle();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    setError(msg);
  }
}
