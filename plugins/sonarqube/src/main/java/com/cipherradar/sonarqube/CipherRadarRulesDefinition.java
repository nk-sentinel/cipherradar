package com.cipherradar.sonarqube;

import org.sonar.api.server.rule.RulesDefinition;

/**
 * Defines the CipherRadar external rule repository in SonarQube.
 *
 * <p>Rules are defined here so that imported external issues reference valid
 * rule keys and can be browsed in the SonarQube rules UI.
 */
public class CipherRadarRulesDefinition implements RulesDefinition {

    public static final String REPOSITORY_KEY = "cipherradar";
    public static final String REPOSITORY_NAME = "CipherRadar";
    public static final String LANGUAGE_KEY = ""; // multi-language

    @Override
    public void define(Context context) {
        // CipherRadar is language-agnostic — create a repository per supported language.
        // For now, register rules under a generic "crypto" repository.
        NewRepository repo = context.createExternalRepository(REPOSITORY_KEY, "java")
                .setName(REPOSITORY_NAME);

        // --- Deprecated algorithms (ERROR severity) ---
        repo.createRule("cbom-weak-hash")
                .setName("Weak Hash Algorithm")
                .setHtmlDescription(
                        "<p>A deprecated hash algorithm (MD5, SHA-1) was detected. "
                                + "These algorithms are cryptographically broken and must not be used "
                                + "for security purposes.</p>"
                                + "<p>Replace with SHA-256, SHA-3, or BLAKE3.</p>")
                .setSeverity("CRITICAL")
                .setType(org.sonar.api.rules.RuleType.VULNERABILITY);

        repo.createRule("cbom-weak-cipher")
                .setName("Weak Cipher Algorithm")
                .setHtmlDescription(
                        "<p>A deprecated cipher algorithm (DES, 3DES, RC4, Blowfish) was detected. "
                                + "These ciphers have known vulnerabilities.</p>"
                                + "<p>Replace with AES-256-GCM or ChaCha20-Poly1305.</p>")
                .setSeverity("CRITICAL")
                .setType(org.sonar.api.rules.RuleType.VULNERABILITY);

        repo.createRule("cbom-weak-key-size")
                .setName("Insufficient Key Size")
                .setHtmlDescription(
                        "<p>A cryptographic key with insufficient size was detected "
                                + "(e.g., RSA-1024, ECDSA P-160). Use at least RSA-2048 or ECDSA P-256.</p>")
                .setSeverity("MAJOR")
                .setType(org.sonar.api.rules.RuleType.VULNERABILITY);

        // --- Quantum-vulnerable algorithms (WARNING severity) ---
        repo.createRule("cbom-quantum-vulnerable")
                .setName("Quantum-Vulnerable Algorithm")
                .setHtmlDescription(
                        "<p>An algorithm vulnerable to quantum computing attacks was detected "
                                + "(RSA, ECDSA, ECDH, DSA, DH). These algorithms will be broken by "
                                + "Shor's algorithm on a sufficiently powerful quantum computer.</p>"
                                + "<p>Plan migration to post-quantum alternatives: ML-KEM, ML-DSA, "
                                + "SLH-DSA.</p>")
                .setSeverity("MAJOR")
                .setType(org.sonar.api.rules.RuleType.CODE_SMELL);

        // --- Informational findings ---
        repo.createRule("cbom-crypto-detected")
                .setName("Cryptographic Asset Detected")
                .setHtmlDescription(
                        "<p>A cryptographic asset was detected in the codebase. "
                                + "This finding is informational and contributes to the "
                                + "Cryptography Bill of Materials (CBOM).</p>")
                .setSeverity("INFO")
                .setType(org.sonar.api.rules.RuleType.CODE_SMELL);

        repo.createRule("cbom-hardcoded-key")
                .setName("Hardcoded Cryptographic Key")
                .setHtmlDescription(
                        "<p>A hardcoded cryptographic key or secret was detected in the source code. "
                                + "Keys should be loaded from a secure key management system, not embedded "
                                + "in source.</p>")
                .setSeverity("BLOCKER")
                .setType(org.sonar.api.rules.RuleType.VULNERABILITY);

        repo.createRule("cbom-insecure-random")
                .setName("Insecure Random Number Generator")
                .setHtmlDescription(
                        "<p>An insecure random number generator (e.g., Math.random(), rand()) "
                                + "is used in a cryptographic context. Use a cryptographically secure "
                                + "PRNG (CSPRNG) instead.</p>")
                .setSeverity("CRITICAL")
                .setType(org.sonar.api.rules.RuleType.VULNERABILITY);

        repo.done();
    }
}
