package com.cipherradar.sonarqube;

import org.sonar.api.Plugin;

/**
 * CipherRadar SonarQube plugin entry point.
 *
 * <p>Registers all extensions:
 * <ul>
 *   <li>{@link CipherRadarRulesDefinition} — rule repository</li>
 *   <li>{@link CipherRadarSensor} — imports SARIF / generic issue reports</li>
 *   <li>{@link CipherRadarPageDefinition} — CBOM dashboard tab</li>
 *   <li>{@link CipherRadarWidget} — dashboard widget</li>
 * </ul>
 */
public class CipherRadarPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtensions(
                CipherRadarRulesDefinition.class,
                CipherRadarSensor.class,
                CipherRadarPageDefinition.class,
                CipherRadarWidget.class
        );
    }
}
