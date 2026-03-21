package com.cipherradar.intellij

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName

/**
 * Parse SARIF 2.1 JSON output from the `cradar` CLI into a list of
 * [CipherRadarFinding] objects.
 */
object SarifParser {

    private val gson = Gson()

    /**
     * Parse a SARIF JSON string and return extracted findings.
     *
     * @param json the raw SARIF 2.1 JSON string from `cradar scan --format sarif`
     * @param defaultFilePath fallback file path when SARIF locations omit it
     * @return list of parsed findings
     */
    fun parse(json: String, defaultFilePath: String): List<CipherRadarFinding> {
        val log = gson.fromJson(json, SarifLog::class.java) ?: return emptyList()
        val findings = mutableListOf<CipherRadarFinding>()

        for (run in log.runs.orEmpty()) {
            for (result in run.results.orEmpty()) {
                val loc = result.locations?.firstOrNull()?.physicalLocation
                val region = loc?.region
                val artifactUri = loc?.artifactLocation?.uri

                val filePath = if (!artifactUri.isNullOrBlank()) {
                    // Resolve relative URI against default path's parent directory
                    val parent = java.io.File(defaultFilePath).parentFile
                    java.io.File(parent, artifactUri).absolutePath
                } else {
                    defaultFilePath
                }

                val props = result.properties

                findings.add(
                    CipherRadarFinding(
                        ruleId = result.ruleId ?: "unknown",
                        message = result.message?.text ?: "",
                        level = mapLevel(result.level, props?.quantumStatus),
                        filePath = filePath,
                        startLine = (region?.startLine ?: 1) - 1,   // 0-based
                        startColumn = (region?.startColumn ?: 1) - 1,
                        endLine = (region?.endLine ?: region?.startLine ?: 1) - 1,
                        endColumn = (region?.endColumn ?: 200) - 1,
                        algorithmName = props?.algorithmName,
                        algorithmFamily = props?.algorithmFamily,
                        quantumStatus = props?.quantumStatus,
                        pqcReplacement = props?.pqcReplacement,
                        complianceTags = props?.complianceTags,
                        findingId = props?.findingId,
                        remediationHint = props?.remediationHint,
                    )
                )
            }
        }

        return findings
    }

    private fun mapLevel(level: String?, quantumStatus: String?): FindingLevel {
        return when {
            level == "error" -> FindingLevel.ERROR
            level == "warning" || quantumStatus == "vulnerable" -> FindingLevel.WARNING
            else -> FindingLevel.INFO
        }
    }
}

// ---------------------------------------------------------------------------
// Finding model
// ---------------------------------------------------------------------------

data class CipherRadarFinding(
    val ruleId: String,
    val message: String,
    val level: FindingLevel,
    val filePath: String,
    val startLine: Int,
    val startColumn: Int,
    val endLine: Int,
    val endColumn: Int,
    val algorithmName: String? = null,
    val algorithmFamily: String? = null,
    val quantumStatus: String? = null,
    val pqcReplacement: String? = null,
    val complianceTags: List<String>? = null,
    val findingId: String? = null,
    val remediationHint: String? = null,
)

enum class FindingLevel {
    ERROR, WARNING, INFO
}

// ---------------------------------------------------------------------------
// SARIF 2.1 data classes (minimal subset)
// ---------------------------------------------------------------------------

data class SarifLog(
    val version: String? = null,
    val runs: List<SarifRun>? = null,
)

data class SarifRun(
    val tool: SarifTool? = null,
    val results: List<SarifResult>? = null,
)

data class SarifTool(
    val driver: SarifToolComponent? = null,
)

data class SarifToolComponent(
    val name: String? = null,
    val version: String? = null,
)

data class SarifResult(
    val ruleId: String? = null,
    val level: String? = null,
    val message: SarifMessage? = null,
    val locations: List<SarifLocation>? = null,
    val properties: SarifResultProperties? = null,
)

data class SarifMessage(
    val text: String? = null,
)

data class SarifLocation(
    val physicalLocation: SarifPhysicalLocation? = null,
)

data class SarifPhysicalLocation(
    val artifactLocation: SarifArtifactLocation? = null,
    val region: SarifRegion? = null,
)

data class SarifArtifactLocation(
    val uri: String? = null,
)

data class SarifRegion(
    val startLine: Int? = null,
    val startColumn: Int? = null,
    val endLine: Int? = null,
    val endColumn: Int? = null,
)

data class SarifResultProperties(
    val algorithmName: String? = null,
    val algorithmFamily: String? = null,
    val quantumStatus: String? = null,
    val pqcReplacement: String? = null,
    val complianceTags: List<String>? = null,
    val findingId: String? = null,
    val remediationHint: String? = null,
)
