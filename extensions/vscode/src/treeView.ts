import * as vscode from "vscode";
import * as path from "path";
import { getAllFindings } from "./diagnostics";
import { CipherRadarFinding, FindingSeverity } from "./types";

// ---------------------------------------------------------------------------
// Tree data provider — findings grouped by severity
// ---------------------------------------------------------------------------

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<FindingTreeItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FindingTreeItem | undefined | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingTreeItem): FindingTreeItem[] {
    if (!element) {
      // Root level: severity groups
      return this.getSeverityGroups();
    }

    if (element.contextValue === "severityGroup") {
      // Second level: individual findings in this severity group
      return this.getFindingsForSeverity(element.severityKey!);
    }

    return [];
  }

  // -----------------------------------------------------------------------
  // Severity group nodes
  // -----------------------------------------------------------------------

  private getSeverityGroups(): FindingTreeItem[] {
    const allFindings = getAllFindings();
    const bySeverity = new Map<FindingSeverity, CipherRadarFinding[]>();

    for (const findings of allFindings.values()) {
      for (const f of findings) {
        const list = bySeverity.get(f.severity) ?? [];
        list.push(f);
        bySeverity.set(f.severity, list);
      }
    }

    const order: FindingSeverity[] = ["error", "warning", "information", "hint"];
    const groups: FindingTreeItem[] = [];

    for (const sev of order) {
      const items = bySeverity.get(sev);
      if (!items || items.length === 0) {
        continue;
      }

      const label = `${severityLabel(sev)} (${items.length})`;
      const item = new FindingTreeItem(
        label,
        vscode.TreeItemCollapsibleState.Expanded,
      );
      item.contextValue = "severityGroup";
      item.severityKey = sev;
      item.iconPath = severityIcon(sev);
      groups.push(item);
    }

    if (groups.length === 0) {
      const empty = new FindingTreeItem(
        "No findings",
        vscode.TreeItemCollapsibleState.None,
      );
      empty.contextValue = "empty";
      return [empty];
    }

    return groups;
  }

  // -----------------------------------------------------------------------
  // Finding leaf nodes
  // -----------------------------------------------------------------------

  private getFindingsForSeverity(severity: FindingSeverity): FindingTreeItem[] {
    const allFindings = getAllFindings();
    const items: FindingTreeItem[] = [];

    for (const [uriStr, findings] of allFindings) {
      for (const f of findings) {
        if (f.severity !== severity) {
          continue;
        }

        const uri = vscode.Uri.parse(uriStr);
        const fileName = path.basename(uri.fsPath);
        const line = f.range.startLine + 1;
        const label = `${fileName}:${line} — ${f.algorithmName ?? f.ruleId}`;

        const item = new FindingTreeItem(
          label,
          vscode.TreeItemCollapsibleState.None,
        );
        item.contextValue = "finding";
        item.tooltip = f.message;
        item.description = f.quantumStatus ?? "";
        item.command = {
          command: "vscode.open",
          title: "Go to finding",
          arguments: [
            uri,
            {
              selection: new vscode.Range(
                f.range.startLine,
                f.range.startColumn,
                f.range.endLine,
                f.range.endColumn,
              ),
            },
          ],
        };
        items.push(item);
      }
    }

    return items;
  }
}

// ---------------------------------------------------------------------------
// Tree item
// ---------------------------------------------------------------------------

class FindingTreeItem extends vscode.TreeItem {
  severityKey?: FindingSeverity;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityLabel(sev: FindingSeverity): string {
  switch (sev) {
    case "error":
      return "Errors";
    case "warning":
      return "Warnings";
    case "information":
      return "Information";
    case "hint":
      return "Hints";
  }
}

function severityIcon(
  sev: FindingSeverity,
): vscode.ThemeIcon {
  switch (sev) {
    case "error":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    case "warning":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    case "information":
      return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
    case "hint":
      return new vscode.ThemeIcon("lightbulb");
  }
}
