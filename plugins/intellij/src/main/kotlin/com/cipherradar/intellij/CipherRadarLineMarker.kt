package com.cipherradar.intellij

import com.intellij.codeInsight.daemon.LineMarkerInfo
import com.intellij.codeInsight.daemon.LineMarkerProvider
import com.intellij.icons.AllIcons
import com.intellij.openapi.editor.markup.GutterIconRenderer
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import javax.swing.Icon

/**
 * Gutter icon line marker provider — shows icons in the editor gutter
 * for lines that have CipherRadar findings.
 *
 * Icons are severity-mapped:
 * - Error (deprecated algorithm): red error icon
 * - Warning (quantum-vulnerable): yellow warning icon
 * - Info (quantum-safe): blue info icon
 */
class CipherRadarLineMarker : LineMarkerProvider {

    override fun getLineMarkerInfo(element: PsiElement): LineMarkerInfo<*>? {
        // We only attach markers to the first element of a line, which is
        // typically the first leaf PsiElement. To avoid duplicates, only
        // process first-child elements.
        if (element.parent !is PsiFile && element.prevSibling != null) {
            return null
        }

        val file = element.containingFile ?: return null
        val virtualFile = file.virtualFile ?: return null
        val filePath = virtualFile.path

        val document = file.viewProvider.document ?: return null
        val elementLine = document.getLineNumber(element.textRange.startOffset)

        // Look up cached findings for this file and line
        val findings = getCachedFindingsForFile(filePath)
        val finding = findings.firstOrNull { it.startLine == elementLine } ?: return null

        val icon = findingIcon(finding.level)
        val tooltipText = buildGutterTooltip(finding)

        return LineMarkerInfo(
            element,
            element.textRange,
            icon,
            { tooltipText },
            null,
            GutterIconRenderer.Alignment.LEFT,
            { tooltipText },
        )
    }

    companion object {
        /**
         * Retrieve cached findings for a file from the annotator's cache.
         * This avoids re-running the CLI for gutter icons.
         */
        private fun getCachedFindingsForFile(filePath: String): List<CipherRadarFinding> {
            // Access the annotator's internal cache via reflection-free approach:
            // The CipherRadarAnnotator stores results in a companion cache.
            // For the line marker, we access a shared finding store.
            return FindingStore.getFindings(filePath)
        }

        private fun findingIcon(level: FindingLevel): Icon {
            return when (level) {
                FindingLevel.ERROR -> AllIcons.General.Error
                FindingLevel.WARNING -> AllIcons.General.Warning
                FindingLevel.INFO -> AllIcons.General.Information
            }
        }

        private fun buildGutterTooltip(finding: CipherRadarFinding): String {
            val parts = mutableListOf<String>()
            parts.add("CipherRadar: ${finding.ruleId}")
            parts.add(finding.message)
            finding.algorithmName?.let { parts.add("Algorithm: $it") }
            finding.quantumStatus?.let { parts.add("Quantum: $it") }
            return parts.joinToString("\n")
        }
    }
}

/**
 * Simple thread-safe finding store shared between the annotator and
 * the line marker provider.
 */
object FindingStore {
    private val store = java.util.concurrent.ConcurrentHashMap<String, List<CipherRadarFinding>>()

    fun putFindings(filePath: String, findings: List<CipherRadarFinding>) {
        store[filePath] = findings
    }

    fun getFindings(filePath: String): List<CipherRadarFinding> {
        return store[filePath] ?: emptyList()
    }

    fun clear() {
        store.clear()
    }
}
