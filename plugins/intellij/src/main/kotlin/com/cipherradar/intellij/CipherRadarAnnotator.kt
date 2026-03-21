package com.cipherradar.intellij

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.OSProcessHandler
import com.intellij.execution.process.ProcessAdapter
import com.intellij.execution.process.ProcessEvent
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.util.Key
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile
import java.util.concurrent.ConcurrentHashMap

/**
 * External Annotator that integrates the `cradar` CLI with IntelliJ's
 * annotation framework.
 *
 * Threading model (per ADR-030):
 * - [collectInformation] runs on EDT — collects file path, must be fast
 * - [doAnnotate] runs on a background thread — invokes CLI, parses SARIF
 * - [apply] runs on EDT — creates annotations from results
 */
class CipherRadarAnnotator :
    ExternalAnnotator<CipherRadarAnnotator.CollectedInfo, CipherRadarAnnotator.AnnotationResult>() {

    /**
     * Lightweight data collected on the EDT.
     */
    data class CollectedInfo(
        val filePath: String,
        val documentText: String,
        val modificationStamp: Long,
    )

    /**
     * Result produced on a background thread.
     */
    data class AnnotationResult(
        val findings: List<CipherRadarFinding>,
    )

    companion object {
        /** Cache of recent scan results keyed by (filePath, modStamp). */
        private val cache = ConcurrentHashMap<String, Pair<Long, List<CipherRadarFinding>>>()
    }

    // -----------------------------------------------------------------------
    // Phase 1: collectInformation (EDT)
    // -----------------------------------------------------------------------

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): CollectedInfo? {
        val virtualFile = file.virtualFile ?: return null
        val path = virtualFile.path
        val document = editor.document

        return CollectedInfo(
            filePath = path,
            documentText = document.text,
            modificationStamp = document.modificationStamp,
        )
    }

    // -----------------------------------------------------------------------
    // Phase 2: doAnnotate (background thread)
    // -----------------------------------------------------------------------

    override fun doAnnotate(info: CollectedInfo?): AnnotationResult? {
        if (info == null) return null

        // Check cache
        val cached = cache[info.filePath]
        if (cached != null && cached.first == info.modificationStamp) {
            return AnnotationResult(cached.second)
        }

        // Run cradar CLI
        val settings = CipherRadarSettings.getInstance().state
        val sarifJson = runCradarScan(settings.cradarPath, info.filePath) ?: return null

        val findings = SarifParser.parse(sarifJson, info.filePath)

        // Update cache
        cache[info.filePath] = info.modificationStamp to findings

        return AnnotationResult(findings)
    }

    // -----------------------------------------------------------------------
    // Phase 3: apply (EDT)
    // -----------------------------------------------------------------------

    override fun apply(file: PsiFile, result: AnnotationResult?, holder: AnnotationHolder) {
        if (result == null) return

        val document = file.viewProvider.document ?: return
        val settings = CipherRadarSettings.getInstance().state
        val minSeverity = mapMinSeverity(settings.minSeverity)

        for (finding in result.findings) {
            val severity = mapFindingSeverity(finding.level)
            if (severity < minSeverity) continue

            // Compute text range from line/column (0-based)
            val startOffset = safeOffset(document, finding.startLine, finding.startColumn)
            val endOffset = safeOffset(document, finding.endLine, finding.endColumn)
            if (startOffset >= endOffset || startOffset < 0) continue

            val textRange = TextRange(startOffset, endOffset.coerceAtMost(document.textLength))

            // Build tooltip
            val tooltip = buildTooltip(finding)

            holder.newAnnotation(severity, finding.message)
                .range(textRange)
                .tooltip(tooltip)
                .withFix(CipherRadarQuickFix.SuppressFix(finding))
                .apply {
                    if (settings.apiUrl.isNotBlank() && finding.findingId != null) {
                        withFix(CipherRadarQuickFix.RemediateFix(finding))
                    }
                }
                .create()
        }
    }

    // -----------------------------------------------------------------------
    // CLI subprocess
    // -----------------------------------------------------------------------

    private fun runCradarScan(binaryPath: String, filePath: String): String? {
        return try {
            val commandLine = GeneralCommandLine(
                binaryPath, "scan", "--format", "sarif", "--file", filePath
            ).withWorkDirectory(java.io.File(filePath).parentFile)

            val output = StringBuilder()
            val handler = OSProcessHandler(commandLine)

            handler.addProcessListener(object : ProcessAdapter() {
                override fun onTextAvailable(event: ProcessEvent, outputType: Key<*>) {
                    output.append(event.text)
                }
            })

            handler.startNotify()
            handler.waitFor(60_000) // 60 second timeout

            if (handler.exitCode == 0) output.toString() else null
        } catch (e: Exception) {
            null
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun safeOffset(document: com.intellij.openapi.editor.Document, line: Int, column: Int): Int {
        if (line < 0 || line >= document.lineCount) return 0
        val lineStartOffset = document.getLineStartOffset(line)
        val lineEndOffset = document.getLineEndOffset(line)
        return (lineStartOffset + column).coerceIn(lineStartOffset, lineEndOffset)
    }

    private fun buildTooltip(finding: CipherRadarFinding): String {
        val parts = mutableListOf<String>()
        parts.add("<b>CipherRadar: ${finding.ruleId}</b>")
        parts.add(finding.message)

        finding.algorithmName?.let { parts.add("Algorithm: $it") }
        finding.algorithmFamily?.let { parts.add("Type: $it") }
        finding.quantumStatus?.let {
            val icon = when (it) {
                "safe" -> "&#9989;"      // green check
                "vulnerable" -> "&#9888;" // warning
                else -> "&#10067;"        // question
            }
            parts.add("Quantum status: $icon ${it.replaceFirstChar { c -> c.uppercase() }}")
        }
        finding.pqcReplacement?.let { parts.add("PQC replacement: <code>$it</code>") }
        finding.remediationHint?.let { parts.add("<br>Remediation: $it") }

        return "<html>${parts.joinToString("<br>")}</html>"
    }

    private fun mapFindingSeverity(level: FindingLevel): HighlightSeverity {
        return when (level) {
            FindingLevel.ERROR -> HighlightSeverity.ERROR
            FindingLevel.WARNING -> HighlightSeverity.WARNING
            FindingLevel.INFO -> HighlightSeverity.INFORMATION
        }
    }

    private fun mapMinSeverity(level: String): HighlightSeverity {
        return when (level) {
            "error" -> HighlightSeverity.ERROR
            "warning" -> HighlightSeverity.WARNING
            else -> HighlightSeverity.INFORMATION
        }
    }
}
