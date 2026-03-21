import * as vscode from "vscode";
import { getCachedFindings } from "./diagnostics";
import { CipherRadarFinding } from "./types";

/**
 * HoverProvider — when the cursor hovers over a range that contains a
 * CipherRadar finding, display algorithm details and quantum status.
 */
export class CipherRadarHoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken,
  ): vscode.Hover | undefined {
    const findings = getCachedFindings(document.uri);
    if (findings.length === 0) {
      return undefined;
    }

    // Find the first finding whose range contains the hover position.
    const hit = findings.find((f) => {
      const range = new vscode.Range(
        f.range.startLine,
        f.range.startColumn,
        f.range.endLine,
        f.range.endColumn,
      );
      return range.contains(position);
    });

    if (!hit) {
      return undefined;
    }

    const md = buildHoverMarkdown(hit);
    const hoverRange = new vscode.Range(
      hit.range.startLine,
      hit.range.startColumn,
      hit.range.endLine,
      hit.range.endColumn,
    );

    return new vscode.Hover(md, hoverRange);
  }
}

// ---------------------------------------------------------------------------
// Markdown builder
// ---------------------------------------------------------------------------

function buildHoverMarkdown(finding: CipherRadarFinding): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = true;
  md.supportHtml = true;

  // Header
  md.appendMarkdown(`### CipherRadar Finding\n\n`);

  // Rule & message
  md.appendMarkdown(`**Rule:** \`${finding.ruleId}\`\n\n`);
  md.appendMarkdown(`${finding.message}\n\n`);

  // Algorithm details
  if (finding.algorithmName) {
    md.appendMarkdown(`**Algorithm:** ${finding.algorithmName}\n\n`);
  }
  if (finding.algorithmFamily) {
    md.appendMarkdown(`**Type:** ${finding.algorithmFamily}\n\n`);
  }

  // Quantum status
  if (finding.quantumStatus) {
    const icon = quantumStatusIcon(finding.quantumStatus);
    const label = finding.quantumStatus.charAt(0).toUpperCase() + finding.quantumStatus.slice(1);
    md.appendMarkdown(`**Quantum Status:** ${icon} ${label}\n\n`);
  }

  // PQC replacement
  if (finding.pqcReplacement) {
    md.appendMarkdown(
      `**Recommended PQC Replacement:** \`${finding.pqcReplacement}\`\n\n`,
    );
  }

  // Compliance
  if (finding.complianceTags && finding.complianceTags.length > 0) {
    md.appendMarkdown(
      `**Compliance:** ${finding.complianceTags.join(", ")}\n\n`,
    );
  }

  // Remediation hint
  if (finding.remediationHint) {
    md.appendMarkdown(`---\n\n`);
    md.appendMarkdown(`**Remediation:** ${finding.remediationHint}\n\n`);
  }

  return md;
}

function quantumStatusIcon(status: string): string {
  switch (status) {
    case "safe":
      return "$(pass)";
    case "vulnerable":
      return "$(warning)";
    default:
      return "$(question)";
  }
}
