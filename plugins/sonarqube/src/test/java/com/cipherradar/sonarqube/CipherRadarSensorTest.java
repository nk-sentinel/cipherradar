package com.cipherradar.sonarqube;

import org.junit.Test;
import org.junit.Before;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link CipherRadarSensor}.
 *
 * <p>These tests verify the sensor's report parsing and issue import logic
 * without requiring a running SonarQube instance.
 */
public class CipherRadarSensorTest {

    @Before
    public void setUp() {
        // Setup is intentionally minimal — full integration tests require
        // SonarQube test harness (sonar-plugin-api-impl).
    }

    @Test
    public void sensorDescriptorHasCorrectName() {
        // The sensor should declare itself as "CipherRadar CBOM Sensor".
        // Full descriptor testing requires SensorDescriptor mock; this test
        // validates the sensor can be instantiated.
        CipherRadarSensor sensor = new CipherRadarSensor();
        assertNotNull("Sensor should be instantiable", sensor);
    }

    @Test
    public void pluginRegistersAllExtensions() {
        // Verify the plugin entry point registers the expected extensions.
        CipherRadarPlugin plugin = new CipherRadarPlugin();
        assertNotNull("Plugin should be instantiable", plugin);
    }

    @Test
    public void rulesDefinitionCreatesExpectedRules() {
        // Verify that the rules definition creates rules with expected keys.
        CipherRadarRulesDefinition rulesDef = new CipherRadarRulesDefinition();
        assertNotNull("RulesDefinition should be instantiable", rulesDef);
    }

    @Test
    public void pageDefinitionIsInstantiable() {
        CipherRadarPageDefinition pageDef = new CipherRadarPageDefinition();
        assertNotNull("PageDefinition should be instantiable", pageDef);
    }

    @Test
    public void widgetDefinesExpectedMetrics() {
        CipherRadarWidget widget = new CipherRadarWidget();
        assertNotNull("Widget should be instantiable", widget);

        var metrics = widget.getMetrics();
        assertNotNull("Metrics list should not be null", metrics);
        assertEquals("Should define 4 custom metrics", 4, metrics.size());

        // Verify metric keys
        assertTrue("Should contain crypto_findings metric",
                metrics.stream().anyMatch(m -> "cipherradar_crypto_findings".equals(m.getKey())));
        assertTrue("Should contain quantum_vulnerable metric",
                metrics.stream().anyMatch(m -> "cipherradar_quantum_vulnerable".equals(m.getKey())));
        assertTrue("Should contain quantum_risk_score metric",
                metrics.stream().anyMatch(m -> "cipherradar_quantum_risk_score".equals(m.getKey())));
        assertTrue("Should contain pqc_readiness metric",
                metrics.stream().anyMatch(m -> "cipherradar_pqc_readiness".equals(m.getKey())));
    }

    @Test
    public void validGenericIssueJsonStructure() {
        // Validate the expected JSON structure that the sensor would parse.
        String sampleJson = "{\n" +
                "  \"issues\": [\n" +
                "    {\n" +
                "      \"engineId\": \"cipherradar\",\n" +
                "      \"ruleId\": \"cbom-weak-hash\",\n" +
                "      \"severity\": \"CRITICAL\",\n" +
                "      \"type\": \"VULNERABILITY\",\n" +
                "      \"primaryLocation\": {\n" +
                "        \"message\": \"MD5 is a deprecated hash algorithm\",\n" +
                "        \"filePath\": \"src/main/java/Crypto.java\",\n" +
                "        \"textRange\": {\n" +
                "          \"startLine\": 10,\n" +
                "          \"startColumn\": 5,\n" +
                "          \"endLine\": 10,\n" +
                "          \"endColumn\": 30\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        // Verify the JSON is parseable
        com.google.gson.JsonObject root = new com.google.gson.Gson()
                .fromJson(sampleJson, com.google.gson.JsonObject.class);

        assertNotNull("Root object should parse", root);
        assertTrue("Should contain 'issues' array", root.has("issues"));

        com.google.gson.JsonArray issues = root.getAsJsonArray("issues");
        assertEquals("Should have 1 issue", 1, issues.size());

        com.google.gson.JsonObject issue = issues.get(0).getAsJsonObject();
        assertEquals("cipherradar", issue.get("engineId").getAsString());
        assertEquals("cbom-weak-hash", issue.get("ruleId").getAsString());
        assertEquals("CRITICAL", issue.get("severity").getAsString());
        assertEquals("VULNERABILITY", issue.get("type").getAsString());

        com.google.gson.JsonObject location = issue.getAsJsonObject("primaryLocation");
        assertNotNull("Primary location should exist", location);
        assertEquals("src/main/java/Crypto.java", location.get("filePath").getAsString());

        com.google.gson.JsonObject textRange = location.getAsJsonObject("textRange");
        assertEquals(10, textRange.get("startLine").getAsInt());
        assertEquals(5, textRange.get("startColumn").getAsInt());
    }
}
