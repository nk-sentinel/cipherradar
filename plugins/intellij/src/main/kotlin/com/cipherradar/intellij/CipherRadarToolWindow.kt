package com.cipherradar.intellij

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.OSProcessHandler
import com.intellij.execution.process.ProcessAdapter
import com.intellij.execution.process.ProcessEvent
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Key
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.treeStructure.Tree
import java.awt.BorderLayout
import javax.swing.*
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel

/**
 * Tool window showing all CipherRadar findings in the current project,
 * grouped by severity. Double-click navigates to the finding location.
 */
class CipherRadarToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = CipherRadarToolWindowPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Findings", false)
        toolWindow.contentManager.addContent(content)
    }
}

class CipherRadarToolWindowPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val rootNode = DefaultMutableTreeNode("CipherRadar Findings")
    private val treeModel = DefaultTreeModel(rootNode)
    private val tree = Tree(treeModel)

    // Map tree nodes to findings for navigation
    private val nodeToFinding = mutableMapOf<DefaultMutableTreeNode, CipherRadarFinding>()

    init {
        // Toolbar
        val toolbar = JPanel()
        toolbar.layout = BoxLayout(toolbar, BoxLayout.X_AXIS)

        val refreshButton = JButton("Rescan Project")
        refreshButton.addActionListener { rescanProject() }
        toolbar.add(refreshButton)

        val clearButton = JButton("Clear")
        clearButton.addActionListener { clearFindings() }
        toolbar.add(clearButton)

        add(toolbar, BorderLayout.NORTH)

        // Tree
        tree.isRootVisible = false
        tree.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseClicked(e: java.awt.event.MouseEvent) {
                if (e.clickCount == 2) {
                    navigateToSelectedFinding()
                }
            }
        })

        add(JBScrollPane(tree), BorderLayout.CENTER)
    }

    private fun rescanProject() {
        val basePath = project.basePath ?: return
        val settings = CipherRadarSettings.getInstance().state

        // Run cradar scan on the whole project in a background thread
        Thread {
            try {
                val commandLine = GeneralCommandLine(
                    settings.cradarPath, "scan", "--format", "sarif"
                ).withWorkDirectory(java.io.File(basePath))

                val output = StringBuilder()
                val handler = OSProcessHandler(commandLine)

                handler.addProcessListener(object : ProcessAdapter() {
                    override fun onTextAvailable(event: ProcessEvent, outputType: Key<*>) {
                        output.append(event.text)
                    }
                })

                handler.startNotify()
                handler.waitFor(120_000)

                if (handler.exitCode == 0) {
                    val findings = SarifParser.parse(output.toString(), basePath)
                    SwingUtilities.invokeLater { updateTree(findings) }
                }
            } catch (_: Exception) {
                // silently fail — tool window will remain empty
            }
        }.start()
    }

    private fun updateTree(findings: List<CipherRadarFinding>) {
        rootNode.removeAllChildren()
        nodeToFinding.clear()

        // Group by severity
        val grouped = findings.groupBy { it.level }
        val order = listOf(FindingLevel.ERROR, FindingLevel.WARNING, FindingLevel.INFO)

        for (level in order) {
            val items = grouped[level] ?: continue
            val label = when (level) {
                FindingLevel.ERROR -> "Errors (${items.size})"
                FindingLevel.WARNING -> "Warnings (${items.size})"
                FindingLevel.INFO -> "Info (${items.size})"
            }

            val severityNode = DefaultMutableTreeNode(label)

            for (finding in items) {
                val fileName = java.io.File(finding.filePath).name
                val line = finding.startLine + 1
                val nodeLabel = "$fileName:$line - ${finding.algorithmName ?: finding.ruleId}"
                val findingNode = DefaultMutableTreeNode(nodeLabel)
                nodeToFinding[findingNode] = finding
                severityNode.add(findingNode)
            }

            rootNode.add(severityNode)
        }

        treeModel.reload()
        // Expand all severity groups
        for (i in 0 until tree.rowCount) {
            tree.expandRow(i)
        }
    }

    private fun clearFindings() {
        rootNode.removeAllChildren()
        nodeToFinding.clear()
        treeModel.reload()
    }

    private fun navigateToSelectedFinding() {
        val selectedNode = tree.lastSelectedPathComponent as? DefaultMutableTreeNode ?: return
        val finding = nodeToFinding[selectedNode] ?: return

        val virtualFile = LocalFileSystem.getInstance().findFileByPath(finding.filePath) ?: return
        val descriptor = OpenFileDescriptor(project, virtualFile, finding.startLine, finding.startColumn)
        FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
    }
}
