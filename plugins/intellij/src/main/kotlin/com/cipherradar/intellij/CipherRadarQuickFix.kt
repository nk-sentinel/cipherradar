package com.cipherradar.intellij

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.ide.BrowserUtil
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiFile
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * Quick-fix intention actions attached to CipherRadar annotations.
 */
object CipherRadarQuickFix {

    /**
     * Suppress a finding by inserting `// cradar:ignore <rule-id>` above the line.
     */
    class SuppressFix(private val finding: CipherRadarFinding) : IntentionAction {

        override fun getText(): String = "Suppress: ${finding.ruleId}"

        override fun getFamilyName(): String = "CipherRadar"

        override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?): Boolean = true

        override fun startInWriteAction(): Boolean = false

        override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
            if (editor == null || file == null) return

            val document = editor.document
            val lineNumber = finding.startLine
            if (lineNumber < 0 || lineNumber >= document.lineCount) return

            val lineStartOffset = document.getLineStartOffset(lineNumber)
            val lineText = document.getText(
                com.intellij.openapi.util.TextRange(
                    lineStartOffset,
                    document.getLineEndOffset(lineNumber)
                )
            )

            // Determine indentation of the finding line
            val indent = lineText.takeWhile { it == ' ' || it == '\t' }
            val suppressComment = "${indent}// cradar:ignore ${finding.ruleId}\n"

            WriteCommandAction.runWriteCommandAction(project) {
                document.insertString(lineStartOffset, suppressComment)
            }
        }
    }

    /**
     * Request LLM-assisted remediation from the CipherRadar backend API.
     */
    class RemediateFix(private val finding: CipherRadarFinding) : IntentionAction {

        override fun getText(): String = "Fix with CipherRadar"

        override fun getFamilyName(): String = "CipherRadar"

        override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?): Boolean {
            val settings = CipherRadarSettings.getInstance().state
            return settings.apiUrl.isNotBlank() && finding.findingId != null
        }

        override fun startInWriteAction(): Boolean = false

        override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
            if (editor == null || file == null || finding.findingId == null) return

            val settings = CipherRadarSettings.getInstance().state
            val apiUrl = settings.apiUrl.trimEnd('/')
            val findingId = finding.findingId

            // Call the backend in a background thread
            com.intellij.openapi.application.ApplicationManager.getApplication()
                .executeOnPooledThread {
                    try {
                        val url = "$apiUrl/findings/$findingId/remediate"

                        val requestBuilder = HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .header("Content-Type", "application/json")
                            .header("Accept", "application/json")

                        if (settings.apiKey.isNotBlank()) {
                            requestBuilder.header("Authorization", "Bearer ${settings.apiKey}")
                        }

                        val client = HttpClient.newHttpClient()
                        val response = client.send(
                            requestBuilder.build(),
                            HttpResponse.BodyHandlers.ofString()
                        )

                        if (response.statusCode() == 200) {
                            val body = response.body()
                            // Parse the patch from the response
                            val gson = com.google.gson.Gson()
                            val result = gson.fromJson(body, RemediationResponse::class.java)

                            if (result.patch.isNotBlank()) {
                                // Apply the patch on the EDT
                                com.intellij.openapi.application.ApplicationManager.getApplication()
                                    .invokeLater {
                                        applyPatch(project, editor, result.patch)
                                    }
                            }
                        }
                    } catch (_: Exception) {
                        // Show notification on EDT
                        com.intellij.openapi.application.ApplicationManager.getApplication()
                            .invokeLater {
                                com.intellij.openapi.ui.Messages.showErrorDialog(
                                    project,
                                    "Failed to fetch remediation from CipherRadar backend.",
                                    "CipherRadar"
                                )
                            }
                    }
                }
        }

        private fun applyPatch(project: Project, editor: Editor, patch: String) {
            val document = editor.document
            val result = com.intellij.openapi.ui.Messages.showYesNoDialog(
                project,
                "Apply the suggested fix from CipherRadar?",
                "CipherRadar Remediation",
                com.intellij.openapi.ui.Messages.getQuestionIcon()
            )

            if (result == com.intellij.openapi.ui.Messages.YES) {
                WriteCommandAction.runWriteCommandAction(project) {
                    document.setText(patch)
                }
            }
        }
    }

    /**
     * Open the finding in the CipherRadar web dashboard.
     */
    class ViewInDashboard(private val finding: CipherRadarFinding) : IntentionAction {

        override fun getText(): String = "View in CipherRadar dashboard"

        override fun getFamilyName(): String = "CipherRadar"

        override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?): Boolean {
            val settings = CipherRadarSettings.getInstance().state
            return settings.apiUrl.isNotBlank() && finding.findingId != null
        }

        override fun startInWriteAction(): Boolean = false

        override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
            val settings = CipherRadarSettings.getInstance().state
            val apiUrl = settings.apiUrl.trimEnd('/')
            val dashboardUrl = apiUrl.replace("/api/v1", "") + "/findings/${finding.findingId}"
            BrowserUtil.browse(dashboardUrl)
        }
    }
}

private data class RemediationResponse(
    val patch: String = "",
    val explanation: String? = null,
)
