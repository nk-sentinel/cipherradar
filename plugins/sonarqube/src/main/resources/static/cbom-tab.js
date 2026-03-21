/**
 * CipherRadar CBOM Tab — SonarQube web extension.
 *
 * Fetches CipherRadar metrics for the current project via the SonarQube
 * Web API and populates the CBOM dashboard tab.
 */
(function () {
    "use strict";

    // SonarQube injects the project key via the page context
    var componentKey = getComponentKey();

    if (!componentKey) {
        console.warn("CipherRadar: unable to determine project component key");
        return;
    }

    fetchMetrics(componentKey);

    /**
     * Extract the component key from the SonarQube page URL.
     */
    function getComponentKey() {
        // SonarQube URLs follow the pattern: /project/extension/cipherradar/cbom?id=<key>
        var params = new URLSearchParams(window.location.search);
        return params.get("id") || params.get("key") || null;
    }

    /**
     * Fetch CipherRadar metrics from the SonarQube Web API.
     */
    function fetchMetrics(key) {
        var metricKeys = [
            "cipherradar_crypto_findings",
            "cipherradar_quantum_vulnerable",
            "cipherradar_quantum_risk_score",
            "cipherradar_pqc_readiness"
        ].join(",");

        var url = "/api/measures/component?component=" +
            encodeURIComponent(key) +
            "&metricKeys=" + encodeURIComponent(metricKeys);

        fetch(url)
            .then(function (response) {
                if (!response.ok) {
                    throw new Error("HTTP " + response.status);
                }
                return response.json();
            })
            .then(function (data) {
                updateDashboard(data);
            })
            .catch(function (err) {
                console.error("CipherRadar: failed to fetch metrics:", err);
            });

        // Also fetch issue counts by severity
        fetchIssueCounts(key);
    }

    /**
     * Fetch issue counts grouped by severity.
     */
    function fetchIssueCounts(key) {
        var url = "/api/issues/search?componentKeys=" +
            encodeURIComponent(key) +
            "&rules=external_cipherradar:*" +
            "&facets=severities" +
            "&ps=1"; // We only need facets, not actual issues

        fetch(url)
            .then(function (response) { return response.json(); })
            .then(function (data) {
                updateSeverityCounts(data);
            })
            .catch(function (err) {
                console.error("CipherRadar: failed to fetch issue counts:", err);
            });
    }

    /**
     * Update the dashboard with metric values.
     */
    function updateDashboard(data) {
        if (!data || !data.component || !data.component.measures) {
            return;
        }

        var measures = {};
        data.component.measures.forEach(function (m) {
            measures[m.metric] = m.value;
        });

        // Quantum risk score
        var riskScore = parseFloat(measures["cipherradar_quantum_risk_score"] || "0");
        var riskEl = document.getElementById("risk-score-value");
        if (riskEl) {
            riskEl.textContent = Math.round(riskScore);
        }
        var riskFill = document.querySelector(".cbom-risk-fill");
        if (riskFill) {
            riskFill.style.width = riskScore + "%";
        }

        // PQC readiness
        var pqcReadiness = parseFloat(measures["cipherradar_pqc_readiness"] || "0");
        var pqcEl = document.getElementById("pqc-readiness-value");
        if (pqcEl) {
            pqcEl.textContent = Math.round(pqcReadiness) + "%";
        }

        // Quantum vulnerable count
        var vulnCount = parseInt(measures["cipherradar_quantum_vulnerable"] || "0", 10);
        var vulnEl = document.getElementById("pqc-vuln-count");
        if (vulnEl) {
            vulnEl.textContent = vulnCount;
        }

        // Total crypto findings
        var totalFindings = parseInt(measures["cipherradar_crypto_findings"] || "0", 10);
        var safeCount = totalFindings - vulnCount;
        var safeEl = document.getElementById("pqc-safe-count");
        if (safeEl) {
            safeEl.textContent = Math.max(safeCount, 0);
        }
    }

    /**
     * Update the severity count cards from issue facets.
     */
    function updateSeverityCounts(data) {
        if (!data || !data.facets) {
            return;
        }

        var severityFacet = data.facets.find(function (f) {
            return f.property === "severities";
        });

        if (!severityFacet || !severityFacet.values) {
            return;
        }

        var counts = {};
        severityFacet.values.forEach(function (v) {
            counts[v.val] = v.count;
        });

        setCount("count-critical", (counts["BLOCKER"] || 0) + (counts["CRITICAL"] || 0));
        setCount("count-major", counts["MAJOR"] || 0);
        setCount("count-minor", counts["MINOR"] || 0);
        setCount("count-info", counts["INFO"] || 0);
    }

    function setCount(elementId, value) {
        var el = document.getElementById(elementId);
        if (el) {
            el.textContent = value;
        }
    }
})();
