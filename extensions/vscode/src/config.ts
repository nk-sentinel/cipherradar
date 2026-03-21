import * as vscode from "vscode";
import { CipherRadarConfig, FindingSeverity } from "./types";

const SECTION = "cipherradar";

/**
 * Read the current CipherRadar extension configuration from VS Code settings.
 */
export function getConfig(): CipherRadarConfig {
  const cfg = vscode.workspace.getConfiguration(SECTION);

  return {
    cradarPath: cfg.get<string>("cradarPath", "cradar"),
    autoScan: cfg.get<boolean>("autoScan", true),
    apiUrl: cfg.get<string>("apiUrl", ""),
    apiKey: cfg.get<string>("apiKey", ""),
    severityMinLevel: cfg.get<FindingSeverity>("severityMinLevel", "information"),
  };
}

/**
 * Register a listener that fires whenever the extension configuration changes.
 * Returns a disposable that should be pushed onto `context.subscriptions`.
 */
export function onConfigChange(
  callback: (config: CipherRadarConfig) => void,
): vscode.Disposable {
  return vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration(SECTION)) {
      callback(getConfig());
    }
  });
}
