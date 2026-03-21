package com.cipherradar.intellij

import com.intellij.openapi.components.*
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import javax.swing.*

/**
 * Persistent plugin settings stored at the application level.
 */
@State(
    name = "CipherRadarSettings",
    storages = [Storage("CipherRadarSettings.xml")]
)
@Service(Service.Level.APP)
class CipherRadarSettings : PersistentStateComponent<CipherRadarSettings.State> {

    data class State(
        var cradarPath: String = "cradar",
        var apiUrl: String = "",
        var apiKey: String = "",
        var scanOnSave: Boolean = true,
        var minSeverity: String = "info", // "error", "warning", "info"
    )

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    companion object {
        fun getInstance(): CipherRadarSettings =
            service<CipherRadarSettings>()
    }
}

/**
 * Settings UI panel — appears under Settings > Tools > CipherRadar.
 */
class CipherRadarConfigurable : Configurable {

    private var cradarPathField: JTextField? = null
    private var apiUrlField: JTextField? = null
    private var apiKeyField: JTextField? = null
    private var scanOnSaveCheckBox: JCheckBox? = null
    private var minSeverityCombo: JComboBox<String>? = null

    override fun getDisplayName(): String = "CipherRadar"

    override fun createComponent(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)

        val settings = CipherRadarSettings.getInstance().state

        // cradar binary path
        cradarPathField = JTextField(settings.cradarPath, 40)
        panel.add(labeledRow("cradar binary path:", cradarPathField!!))

        // API URL
        apiUrlField = JTextField(settings.apiUrl, 40)
        panel.add(labeledRow("Backend API URL:", apiUrlField!!))

        // API key
        apiKeyField = JTextField(settings.apiKey, 40)
        panel.add(labeledRow("API key:", apiKeyField!!))

        // Scan on save
        scanOnSaveCheckBox = JCheckBox("Scan on save", settings.scanOnSave)
        panel.add(scanOnSaveCheckBox)

        // Minimum severity
        minSeverityCombo = JComboBox(arrayOf("error", "warning", "info"))
        minSeverityCombo!!.selectedItem = settings.minSeverity
        panel.add(labeledRow("Minimum severity:", minSeverityCombo!!))

        return panel
    }

    override fun isModified(): Boolean {
        val settings = CipherRadarSettings.getInstance().state
        return cradarPathField?.text != settings.cradarPath ||
                apiUrlField?.text != settings.apiUrl ||
                apiKeyField?.text != settings.apiKey ||
                scanOnSaveCheckBox?.isSelected != settings.scanOnSave ||
                minSeverityCombo?.selectedItem != settings.minSeverity
    }

    override fun apply() {
        val settings = CipherRadarSettings.getInstance()
        settings.loadState(
            CipherRadarSettings.State(
                cradarPath = cradarPathField?.text ?: "cradar",
                apiUrl = apiUrlField?.text ?: "",
                apiKey = apiKeyField?.text ?: "",
                scanOnSave = scanOnSaveCheckBox?.isSelected ?: true,
                minSeverity = minSeverityCombo?.selectedItem as? String ?: "info",
            )
        )
    }

    override fun reset() {
        val settings = CipherRadarSettings.getInstance().state
        cradarPathField?.text = settings.cradarPath
        apiUrlField?.text = settings.apiUrl
        apiKeyField?.text = settings.apiKey
        scanOnSaveCheckBox?.isSelected = settings.scanOnSave
        minSeverityCombo?.selectedItem = settings.minSeverity
    }

    private fun labeledRow(label: String, component: JComponent): JPanel {
        val row = JPanel()
        row.layout = BoxLayout(row, BoxLayout.X_AXIS)
        row.add(JLabel(label))
        row.add(Box.createHorizontalStrut(8))
        row.add(component)
        row.alignmentX = JComponent.LEFT_ALIGNMENT
        return row
    }
}
