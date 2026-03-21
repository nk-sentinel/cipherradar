package com.cipherradar.sonarqube;

import org.sonar.api.web.page.Context;
import org.sonar.api.web.page.Page;
import org.sonar.api.web.page.PageDefinition;

/**
 * Adds a "CBOM" tab to the SonarQube project navigation.
 *
 * <p>The tab displays:
 * <ul>
 *   <li>Quantum risk score</li>
 *   <li>Finding summary by severity</li>
 *   <li>Compliance status (NIST, FIPS-140-3, etc.)</li>
 *   <li>Post-quantum readiness overview</li>
 * </ul>
 *
 * <p>Static assets (HTML, JS, CSS) are served from {@code static/} in the
 * plugin JAR and loaded via SonarQube's built-in web extension API.
 */
public class CipherRadarPageDefinition implements PageDefinition {

    @Override
    public void define(Context context) {
        context.addPage(
                Page.builder("cipherradar/cbom")
                        .setName("CBOM")
                        .setScope(Page.Scope.COMPONENT)
                        .build()
        );
    }
}
