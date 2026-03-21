package com.cipherradar.intellij

import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.fileEditor.FileDocumentManagerListener
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity
import com.intellij.openapi.vfs.VirtualFile

/**
 * Project startup activity — registers a save listener to trigger
 * automatic re-annotation when the user saves a file (if scan-on-save
 * is enabled in settings).
 */
class CipherRadarStartup : ProjectActivity {

    private val log = Logger.getInstance(CipherRadarStartup::class.java)

    override suspend fun execute(project: Project) {
        log.info("CipherRadar plugin activated for project: ${project.name}")

        // The ExternalAnnotator is triggered automatically by IntelliJ's
        // daemon highlighting pass. For scan-on-save, we listen to document
        // save events and request a re-highlight of the saved file.
        val connection = project.messageBus.connect()
        connection.subscribe(
            FileDocumentManagerListener.TOPIC,
            object : FileDocumentManagerListener {
                override fun beforeDocumentSaving(document: com.intellij.openapi.editor.Document) {
                    val settings = CipherRadarSettings.getInstance().state
                    if (!settings.scanOnSave) return

                    val vFile = FileDocumentManager.getInstance().getFile(document) ?: return
                    requestRehighlight(project, vFile)
                }
            }
        )
    }

    private fun requestRehighlight(project: Project, file: VirtualFile) {
        // DaemonCodeAnalyzer will re-run external annotators on the next pass.
        // We force it by restarting analysis for the file.
        com.intellij.codeInsight.daemon.DaemonCodeAnalyzer.getInstance(project).restart()
    }
}
