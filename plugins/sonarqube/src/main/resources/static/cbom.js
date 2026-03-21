/**
 * CipherRadar CBOM Tab — SonarQube web page extension.
 *
 * Registered via window.registerExtension so SonarQube can mount it
 * inside the project-level "CBOM" navigation tab.
 */
window.registerExtension("cipherradar/cbom", function (options) {
  var el = options.el;
  var componentKey = options.component && options.component.key;

  if (!componentKey) {
    var params = new URLSearchParams(window.location.search);
    componentKey = params.get("id") || params.get("key");
  }

  // Inject styles inline (avoids separate CSS load issues in SQ extensions)
  var style = document.createElement("style");
  style.textContent = CSS_TEXT;
  el.appendChild(style);

  // Build DOM
  var root = document.createElement("div");
  root.id = "cipherradar-cbom";
  root.innerHTML = TEMPLATE;
  el.appendChild(root);

  if (!componentKey) {
    root.querySelector(".cbom-header .cbom-subtitle").textContent =
      "Unable to determine project key.";
    return function () { /* cleanup */ };
  }

  fetchIssueData(componentKey, root);
  fetchMetrics(componentKey, root);

  // Return cleanup function
  return function () {
    while (el.firstChild) el.removeChild(el.firstChild);
  };
});

// ---------------------------------------------------------------------------
// Data fetching
// ---------------------------------------------------------------------------

function fetchIssueData(componentKey, root) {
  // Fetch all CipherRadar external issues with severity facet
  fetch(
    "/api/issues/search?componentKeys=" +
      encodeURIComponent(componentKey) +
      "&rules=" +
      encodeURIComponent(
        "external_cipherradar:cbom-weak-hash," +
        "external_cipherradar:cbom-weak-cipher," +
        "external_cipherradar:cbom-weak-key-size," +
        "external_cipherradar:cbom-quantum-vulnerable," +
        "external_cipherradar:cbom-crypto-detected," +
        "external_cipherradar:cbom-hardcoded-key," +
        "external_cipherradar:cbom-insecure-random"
      ) +
      "&facets=severities&ps=500"
  )
    .then(function (r) { return r.json(); })
    .then(function (data) {
      populateSeverityCounts(data, root);
      populateIssuesTable(data, root);
      computeRiskAndPqc(data, root);
      populateCompliance(data, root);
    })
    .catch(function (err) {
      console.error("CipherRadar: failed to fetch issues:", err);
    });
}

function fetchMetrics(componentKey, root) {
  var metricKeys = [
    "cipherradar_crypto_findings",
    "cipherradar_quantum_vulnerable",
    "cipherradar_quantum_risk_score",
    "cipherradar_pqc_readiness"
  ].join(",");

  fetch(
    "/api/measures/component?component=" +
      encodeURIComponent(componentKey) +
      "&metricKeys=" +
      encodeURIComponent(metricKeys)
  )
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.component && data.component.measures) {
        var m = {};
        data.component.measures.forEach(function (measure) {
          m[measure.metric] = measure.value;
        });
        // Override computed values with sensor-provided values if available
        if (m["cipherradar_quantum_risk_score"]) {
          var score = parseFloat(m["cipherradar_quantum_risk_score"]);
          setText(root, "risk-score-value", Math.round(score));
          setWidth(root, ".cbom-risk-fill", score + "%");
          setRiskColor(root, score);
        }
        if (m["cipherradar_pqc_readiness"]) {
          setText(root, "pqc-readiness-value", Math.round(parseFloat(m["cipherradar_pqc_readiness"])) + "%");
        }
      }
    })
    .catch(function () { /* metrics are optional — issue data is primary */ });
}

// ---------------------------------------------------------------------------
// Populate UI
// ---------------------------------------------------------------------------

function populateSeverityCounts(data, root) {
  if (!data || !data.facets) return;
  var facet = data.facets.find(function (f) { return f.property === "severities"; });
  if (!facet || !facet.values) return;

  var counts = {};
  facet.values.forEach(function (v) { counts[v.val] = v.count; });

  setText(root, "count-critical", (counts["BLOCKER"] || 0) + (counts["CRITICAL"] || 0));
  setText(root, "count-major", counts["MAJOR"] || 0);
  setText(root, "count-minor", counts["MINOR"] || 0);
  setText(root, "count-info", counts["INFO"] || 0);
}

function populateIssuesTable(data, root) {
  var tbody = root.querySelector("#issues-tbody");
  if (!tbody || !data || !data.issues) return;

  if (data.issues.length === 0) {
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    td.colSpan = 4;
    td.style.textAlign = "center";
    td.style.color = "#888";
    td.textContent = "No CipherRadar findings for this project. Run a scan with cradar and import results.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  data.issues.forEach(function (issue) {
    var tr = document.createElement("tr");

    var tdSev = document.createElement("td");
    var badge = document.createElement("span");
    badge.className = "cbom-severity-badge cbom-sev-" + (issue.severity || "INFO").toLowerCase();
    badge.textContent = issue.severity || "INFO";
    tdSev.appendChild(badge);
    tr.appendChild(tdSev);

    var tdRule = document.createElement("td");
    tdRule.textContent = (issue.rule || "").replace("external_cipherradar:", "");
    tr.appendChild(tdRule);

    var tdMsg = document.createElement("td");
    tdMsg.textContent = issue.message || "";
    tr.appendChild(tdMsg);

    var tdFile = document.createElement("td");
    var comp = issue.component || "";
    tdFile.textContent = comp.indexOf(":") !== -1 ? comp.split(":").slice(1).join(":") : comp;
    tdFile.style.fontFamily = "monospace";
    tdFile.style.fontSize = "12px";
    tr.appendChild(tdFile);

    tbody.appendChild(tr);
  });
}

function computeRiskAndPqc(data, root) {
  if (!data || !data.issues) return;
  var issues = data.issues;
  var total = issues.length;

  var quantumVuln = issues.filter(function (i) {
    return (i.rule || "").indexOf("quantum-vulnerable") !== -1;
  }).length;

  var critical = issues.filter(function (i) {
    return i.severity === "CRITICAL" || i.severity === "BLOCKER";
  }).length;

  // Risk score: weighted by severity
  var riskScore = 0;
  if (total > 0) {
    issues.forEach(function (i) {
      switch (i.severity) {
        case "BLOCKER": riskScore += 25; break;
        case "CRITICAL": riskScore += 20; break;
        case "MAJOR": riskScore += 10; break;
        case "MINOR": riskScore += 5; break;
        default: riskScore += 1;
      }
    });
    riskScore = Math.min(100, riskScore);
  }

  setText(root, "risk-score-value", Math.round(riskScore));
  setWidth(root, ".cbom-risk-fill", riskScore + "%");
  setRiskColor(root, riskScore);

  // PQC readiness
  var safeCount = total - quantumVuln;
  var pqcPct = total > 0 ? Math.round((safeCount / total) * 100) : 100;
  setText(root, "pqc-readiness-value", pqcPct + "%");
  setText(root, "pqc-safe-count", safeCount);
  setText(root, "pqc-vuln-count", quantumVuln);
  setText(root, "total-findings", total);
}

function populateCompliance(data, root) {
  if (!data || !data.issues) return;
  var issues = data.issues;
  var total = issues.length;

  var weakHash = issues.filter(function (i) { return (i.rule || "").indexOf("weak-hash") !== -1; }).length;
  var weakCipher = issues.filter(function (i) { return (i.rule || "").indexOf("weak-cipher") !== -1; }).length;
  var weakKey = issues.filter(function (i) { return (i.rule || "").indexOf("weak-key") !== -1; }).length;
  var hardcoded = issues.filter(function (i) { return (i.rule || "").indexOf("hardcoded") !== -1; }).length;
  var quantum = issues.filter(function (i) { return (i.rule || "").indexOf("quantum") !== -1; }).length;
  var criticalIssues = weakHash + weakCipher + weakKey + hardcoded;

  // NIST 800-131A: no deprecated algorithms
  var nistOk = weakHash === 0 && weakCipher === 0 && weakKey === 0;
  setCompliance(root, "nist", nistOk, criticalIssues, total);

  // FIPS 140-3: no weak crypto + no hardcoded keys
  var fipsOk = nistOk && hardcoded === 0;
  setCompliance(root, "fips", fipsOk, criticalIssues + hardcoded, total);

  // PCI DSS 4.0: no weak crypto
  setCompliance(root, "pci", nistOk, criticalIssues, total);

  // CNSA 2.0: no quantum-vulnerable
  var cnsaOk = quantum === 0;
  setCompliance(root, "cnsa", cnsaOk, quantum, total);
}

function setCompliance(root, prefix, isOk, violations, total) {
  var statusEl = root.querySelector("#" + prefix + "-status");
  var coverageEl = root.querySelector("#" + prefix + "-coverage");
  if (statusEl) {
    if (total === 0) {
      statusEl.innerHTML = '<span style="color:#888">No Data</span>';
    } else if (isOk) {
      statusEl.innerHTML = '<span style="color:#4caf50;font-weight:600">Pass</span>';
    } else {
      statusEl.innerHTML = '<span style="color:#f44336;font-weight:600">Fail (' + violations + ' violation' + (violations !== 1 ? 's' : '') + ')</span>';
    }
  }
  if (coverageEl) {
    if (total === 0) {
      coverageEl.textContent = "--";
    } else {
      var pct = Math.round(((total - violations) / total) * 100);
      coverageEl.textContent = pct + "%";
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setText(root, id, value) {
  var el = root.querySelector("#" + id);
  if (el) el.textContent = value;
}

function setWidth(root, selector, width) {
  var el = root.querySelector(selector);
  if (el) el.style.width = width;
}

function setRiskColor(root, score) {
  var el = root.querySelector("#risk-score-value");
  if (!el) return;
  if (score >= 75) el.style.color = "#f44336";
  else if (score >= 50) el.style.color = "#ff9800";
  else if (score >= 25) el.style.color = "#ffeb3b";
  else el.style.color = "#4caf50";
}

// ---------------------------------------------------------------------------
// Template (inline HTML)
// ---------------------------------------------------------------------------

var TEMPLATE = [
  '<div class="cbom-header">',
  '  <h1>Cryptography Bill of Materials</h1>',
  '  <p class="cbom-subtitle">Powered by CipherRadar</p>',
  '</div>',
  '',
  '<div class="cbom-section">',
  '  <h2>Quantum Risk Score</h2>',
  '  <div class="cbom-risk-gauge">',
  '    <div id="risk-score-value" class="cbom-risk-value">0</div>',
  '    <div class="cbom-risk-bar"><div class="cbom-risk-fill" style="width:0%"></div></div>',
  '    <div class="cbom-risk-labels"><span>Low</span><span>Medium</span><span>High</span><span>Critical</span></div>',
  '  </div>',
  '</div>',
  '',
  '<div class="cbom-section">',
  '  <h2>Finding Summary</h2>',
  '  <div class="cbom-summary-grid">',
  '    <div class="cbom-summary-card cbom-severity-critical"><div class="cbom-card-count" id="count-critical">0</div><div class="cbom-card-label">Critical</div></div>',
  '    <div class="cbom-summary-card cbom-severity-major"><div class="cbom-card-count" id="count-major">0</div><div class="cbom-card-label">Major</div></div>',
  '    <div class="cbom-summary-card cbom-severity-minor"><div class="cbom-card-count" id="count-minor">0</div><div class="cbom-card-label">Minor</div></div>',
  '    <div class="cbom-summary-card cbom-severity-info"><div class="cbom-card-count" id="count-info">0</div><div class="cbom-card-label">Info</div></div>',
  '  </div>',
  '</div>',
  '',
  '<div class="cbom-section">',
  '  <h2>Compliance Status</h2>',
  '  <table class="cbom-table">',
  '    <thead><tr><th>Framework</th><th>Status</th><th>Coverage</th></tr></thead>',
  '    <tbody>',
  '      <tr><td>NIST SP 800-131A</td><td id="nist-status">--</td><td id="nist-coverage">--</td></tr>',
  '      <tr><td>FIPS 140-3</td><td id="fips-status">--</td><td id="fips-coverage">--</td></tr>',
  '      <tr><td>PCI DSS 4.0</td><td id="pci-status">--</td><td id="pci-coverage">--</td></tr>',
  '      <tr><td>NSA CNSA 2.0</td><td id="cnsa-status">--</td><td id="cnsa-coverage">--</td></tr>',
  '    </tbody>',
  '  </table>',
  '</div>',
  '',
  '<div class="cbom-section">',
  '  <h2>Post-Quantum Readiness</h2>',
  '  <div class="cbom-pqc-summary">',
  '    <div class="cbom-pqc-gauge"><span id="pqc-readiness-value">--%</span><span class="cbom-pqc-label">of crypto assets are quantum-safe</span></div>',
  '    <div class="cbom-pqc-breakdown">',
  '      <div class="cbom-pqc-row"><span class="cbom-dot cbom-dot-safe"></span><span>Quantum-safe: <strong id="pqc-safe-count">0</strong></span></div>',
  '      <div class="cbom-pqc-row"><span class="cbom-dot cbom-dot-vulnerable"></span><span>Quantum-vulnerable: <strong id="pqc-vuln-count">0</strong></span></div>',
  '      <div class="cbom-pqc-row"><span class="cbom-dot cbom-dot-info"></span><span>Total findings: <strong id="total-findings">0</strong></span></div>',
  '    </div>',
  '  </div>',
  '</div>',
  '',
  '<div class="cbom-section">',
  '  <h2>CipherRadar Findings</h2>',
  '  <table class="cbom-table">',
  '    <thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>File</th></tr></thead>',
  '    <tbody id="issues-tbody"></tbody>',
  '  </table>',
  '</div>'
].join("\n");

// ---------------------------------------------------------------------------
// Inline CSS (embedded so it works without separate CSS file loading)
// ---------------------------------------------------------------------------

var CSS_TEXT = [
  "#cipherradar-cbom { max-width:1100px; margin:0 auto; padding:24px; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#333; }",
  ".cbom-header { margin-bottom:32px; }",
  ".cbom-header h1 { font-size:24px; font-weight:600; margin:0 0 4px 0; }",
  ".cbom-subtitle { font-size:13px; color:#888; margin:0; }",
  ".cbom-section { margin-bottom:24px; border:1px solid #e8e8e8; border-radius:4px; padding:20px; background:#fff; }",
  ".cbom-section h2 { font-size:16px; font-weight:600; margin:0 0 16px 0; color:#236a97; }",
  ".cbom-risk-gauge { text-align:center; }",
  ".cbom-risk-value { font-size:48px; font-weight:700; margin-bottom:8px; }",
  ".cbom-risk-bar { height:12px; background:#e8e8e8; border-radius:6px; overflow:hidden; margin-bottom:8px; }",
  ".cbom-risk-fill { height:100%; border-radius:6px; background:linear-gradient(90deg,#4caf50,#ffeb3b,#ff9800,#f44336); transition:width 0.5s ease; }",
  ".cbom-risk-labels { display:flex; justify-content:space-between; font-size:11px; color:#888; }",
  ".cbom-summary-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }",
  ".cbom-summary-card { text-align:center; padding:16px 8px; border-radius:4px; border:1px solid #e8e8e8; }",
  ".cbom-card-count { font-size:32px; font-weight:700; }",
  ".cbom-card-label { font-size:12px; color:#666; margin-top:4px; }",
  ".cbom-severity-critical { border-left:4px solid #f44336; } .cbom-severity-critical .cbom-card-count { color:#f44336; }",
  ".cbom-severity-major { border-left:4px solid #ff9800; } .cbom-severity-major .cbom-card-count { color:#ff9800; }",
  ".cbom-severity-minor { border-left:4px solid #2196f3; } .cbom-severity-minor .cbom-card-count { color:#2196f3; }",
  ".cbom-severity-info { border-left:4px solid #4caf50; } .cbom-severity-info .cbom-card-count { color:#4caf50; }",
  ".cbom-table { width:100%; border-collapse:collapse; }",
  ".cbom-table th,.cbom-table td { padding:10px 12px; text-align:left; border-bottom:1px solid #e8e8e8; font-size:13px; }",
  ".cbom-table th { font-weight:600; color:#666; background:#fafafa; }",
  ".cbom-pqc-summary { display:flex; align-items:center; gap:40px; }",
  ".cbom-pqc-gauge { display:flex; flex-direction:column; align-items:center; }",
  ".cbom-pqc-gauge span:first-child { font-size:40px; font-weight:700; color:#236a97; }",
  ".cbom-pqc-label { font-size:12px; color:#888; margin-top:4px; }",
  ".cbom-pqc-breakdown { flex:1; }",
  ".cbom-pqc-row { display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:13px; }",
  ".cbom-dot { width:10px; height:10px; border-radius:50%; display:inline-block; }",
  ".cbom-dot-safe { background:#4caf50; } .cbom-dot-vulnerable { background:#f44336; } .cbom-dot-info { background:#2196f3; }",
  ".cbom-severity-badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px; font-weight:600; color:#fff; }",
  ".cbom-sev-blocker,.cbom-sev-critical { background:#f44336; }",
  ".cbom-sev-major { background:#ff9800; }",
  ".cbom-sev-minor { background:#2196f3; }",
  ".cbom-sev-info { background:#4caf50; }",
  "@media(max-width:768px) { .cbom-summary-grid { grid-template-columns:repeat(2,1fr); } .cbom-pqc-summary { flex-direction:column; gap:16px; } }"
].join("\n");
