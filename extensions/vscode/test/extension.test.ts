import * as assert from "assert";
import * as vscode from "vscode";

suite("CipherRadar Extension", () => {
  test("Extension should be present", () => {
    const ext = vscode.extensions.getExtension("nk-sentinel.cipherradar");
    assert.ok(ext, "Extension should be registered");
  });

  test("Extension should activate on startup", async () => {
    const ext = vscode.extensions.getExtension("nk-sentinel.cipherradar");
    assert.ok(ext, "Extension should be registered");

    if (!ext.isActive) {
      await ext.activate();
    }
    assert.ok(ext.isActive, "Extension should be active");
  });

  test("Scan command should be registered", async () => {
    const commands = await vscode.commands.getCommands(true);
    assert.ok(
      commands.includes("cipherradar.scan"),
      "cipherradar.scan command should be registered",
    );
  });

  test("Scan workspace command should be registered", async () => {
    const commands = await vscode.commands.getCommands(true);
    assert.ok(
      commands.includes("cipherradar.scanWorkspace"),
      "cipherradar.scanWorkspace command should be registered",
    );
  });

  test("Clear diagnostics command should be registered", async () => {
    const commands = await vscode.commands.getCommands(true);
    assert.ok(
      commands.includes("cipherradar.clearDiagnostics"),
      "cipherradar.clearDiagnostics command should be registered",
    );
  });

  test("Default configuration values", () => {
    const config = vscode.workspace.getConfiguration("cipherradar");
    assert.strictEqual(config.get("cradarPath"), "cradar");
    assert.strictEqual(config.get("autoScan"), true);
    assert.strictEqual(config.get("apiUrl"), "");
  });

  test("Diagnostic collection should exist", async () => {
    // After activation, the diagnostic collection should be available
    const ext = vscode.extensions.getExtension("nk-sentinel.cipherradar");
    if (ext && !ext.isActive) {
      await ext.activate();
    }

    // The diagnostic collection is created on module load — verify it
    // by checking that the cipherradar.scan command does not throw
    // (it will show a warning if no editor is open, which is expected)
    try {
      await vscode.commands.executeCommand("cipherradar.clearDiagnostics");
    } catch {
      assert.fail("clearDiagnostics command should not throw");
    }
  });
});
