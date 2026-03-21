package com.cipherradar.sonarqube;

import org.sonar.api.measures.CoreMetrics;
import org.sonar.api.measures.Metric;
import org.sonar.api.measures.Metrics;

import java.util.Arrays;
import java.util.List;

/**
 * Dashboard widget that provides CipherRadar-specific metrics for the
 * SonarQube project dashboard.
 *
 * <p>Custom metrics:
 * <ul>
 *   <li>{@code cipherradar_crypto_findings} — total crypto findings</li>
 *   <li>{@code cipherradar_quantum_vulnerable} — quantum-vulnerable finding count</li>
 *   <li>{@code cipherradar_quantum_risk_score} — overall quantum risk score (0-100)</li>
 *   <li>{@code cipherradar_pqc_readiness} — post-quantum readiness percentage</li>
 * </ul>
 */
public class CipherRadarWidget implements Metrics {

    /** Total number of cryptographic findings. */
    public static final Metric<Integer> CRYPTO_FINDINGS = new Metric.Builder(
            "cipherradar_crypto_findings",
            "CipherRadar Crypto Findings",
            Metric.ValueType.INT)
            .setDescription("Total number of cryptographic findings detected by CipherRadar")
            .setDirection(Metric.DIRECTION_WORST)
            .setQualitative(true)
            .setDomain("CipherRadar")
            .create();

    /** Number of quantum-vulnerable findings. */
    public static final Metric<Integer> QUANTUM_VULNERABLE = new Metric.Builder(
            "cipherradar_quantum_vulnerable",
            "Quantum-Vulnerable Findings",
            Metric.ValueType.INT)
            .setDescription("Number of cryptographic findings that are vulnerable to quantum attacks")
            .setDirection(Metric.DIRECTION_WORST)
            .setQualitative(true)
            .setDomain("CipherRadar")
            .create();

    /** Quantum risk score (0 = no risk, 100 = critical risk). */
    public static final Metric<Double> QUANTUM_RISK_SCORE = new Metric.Builder(
            "cipherradar_quantum_risk_score",
            "Quantum Risk Score",
            Metric.ValueType.PERCENT)
            .setDescription("Overall quantum risk score (0 = no risk, 100 = critical)")
            .setDirection(Metric.DIRECTION_WORST)
            .setQualitative(true)
            .setDomain("CipherRadar")
            .setWorstValue(100.0)
            .setBestValue(0.0)
            .create();

    /** Post-quantum readiness percentage (0-100%). */
    public static final Metric<Double> PQC_READINESS = new Metric.Builder(
            "cipherradar_pqc_readiness",
            "PQC Readiness",
            Metric.ValueType.PERCENT)
            .setDescription("Percentage of cryptographic assets that are post-quantum ready")
            .setDirection(Metric.DIRECTION_BETTER)
            .setQualitative(true)
            .setDomain("CipherRadar")
            .setWorstValue(0.0)
            .setBestValue(100.0)
            .create();

    @Override
    public List<Metric> getMetrics() {
        return Arrays.asList(
                CRYPTO_FINDINGS,
                QUANTUM_VULNERABLE,
                QUANTUM_RISK_SCORE,
                PQC_READINESS
        );
    }
}
