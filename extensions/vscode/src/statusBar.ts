import * as vscode from "vscode";
import { getAllFindings } from "./diagnostics";

let statusBarItem: vscode.StatusBarItem;

/**
 * Create and register the CipherRadar status bar item.
 */
export function createStatusBar(
  context: vscode.ExtensionContext,
): vscode.StatusBarItem {
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  statusBarItem.command = "cipherradar.scan";
  statusBarItem.name = "CipherRadar";

  setIdle();
  statusBarItem.show();

  context.subscriptions.push(statusBarItem);
  return statusBarItem;
}

/**
 * Update status bar to "scanning" state.
 */
export function setScanning(): void {
  if (!statusBarItem) {
    return;
  }
  statusBarItem.text = "$(sync~spin) CipherRadar: scanning...";
  statusBarItem.tooltip = "CipherRadar scan in progress";
}

/**
 * Update status bar to idle state with the current finding count.
 */
export function setIdle(): void {
  if (!statusBarItem) {
    return;
  }
  const count = countAllFindings();
  if (count === 0) {
    statusBarItem.text = "$(shield) CipherRadar: 0 findings";
    statusBarItem.tooltip = "CipherRadar — no cryptographic findings";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(shield) CipherRadar: ${count} finding${count === 1 ? "" : "s"}`;
    statusBarItem.tooltip = `CipherRadar — ${count} cryptographic finding${count === 1 ? "" : "s"} detected`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground",
    );
  }
}

/**
 * Update status bar to error state.
 */
export function setError(message: string): void {
  if (!statusBarItem) {
    return;
  }
  statusBarItem.text = "$(error) CipherRadar: error";
  statusBarItem.tooltip = `CipherRadar error: ${message}`;
  statusBarItem.backgroundColor = new vscode.ThemeColor(
    "statusBarItem.errorBackground",
  );
}

// ---------------------------------------------------------------------------

function countAllFindings(): number {
  let total = 0;
  for (const findings of getAllFindings().values()) {
    total += findings.length;
  }
  return total;
}
