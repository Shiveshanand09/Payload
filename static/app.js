// API Payload Diagnostics Tool - Front-end Application Client

// Default Sample Data
const SAMPLES = {
  json: `{
  "api_version": "v1.2",
  "clientName": "Acme Corp",
  "RequestId": "req-9821-xyz",
  "user_account": {
    "Id": 1045,
    "user_email": "admin@acmecorp.com",
    "password_hint": "SuperSecretPassword123",
    "authTokens": {
      "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "awsSecretKey": "AKIA1234567890ABCDEF"
    },
    "profile": {
      "first_name": "John",
      "lastName": "Doe",
      "phone": "+1-555-0199",
      "address": {
        "street": "123 Main St",
        "city": "Metropolis",
        "nested_details": {
          "deep_level_one": {
            "deep_level_two": {
              "level_three_details": {
                "too_deep": true
              }
            }
          }
        }
      }
    }
  },
  "sql_query_param": "SELECT * FROM users WHERE id = 1 OR '1'='1'",
  "raw_xss": "<script>alert('xss')</script>",
  "is_active": true,
  "created_at": "2026-06-21T09:55:00Z",
  "updated_date": "2026-06-21",
  "js_unsafe_number": 9007199254740999,
  "null_field_one": null,
  "null_field_two": null,
  "null_field_three": null
}`,
  xml: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE api [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<ApiResponse version="v1.2">
  <ClientName>Acme Corp</ClientName>
  <request_id>req-9821-xyz</request_id>
  <UserAccount>
    <Id>1045</Id>
    <UserEmail>admin@acmecorp.com</UserEmail>
    <PasswordHint>SuperSecretPassword123</PasswordHint>
    <AuthTokens>
      <Jwt>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c</Jwt>
      <AwsKey>AKIA1234567890ABCDEF</AwsKey>
    </AuthTokens>
    <Profile>
      <FirstName>John</FirstName>
      <lastName>Doe</lastName>
      <Phone>+1-555-0199</Phone>
      <Address>
        <Street>123 Main St</Street>
        <City>Metropolis</City>
        <NestedDetails>
          <DeepLevelOne>
            <DeepLevelTwo>
              <LevelThreeDetails>
                <TooDeep>true</TooDeep>
              </LevelThreeDetails>
            </DeepLevelTwo>
          </DeepLevelOne>
        </NestedDetails>
      </Address>
    </Profile>
  </UserAccount>
  <SqlQueryParam>SELECT * FROM users WHERE id = 1 OR '1'='1'</SqlQueryParam>
  <RawXss>&lt;script&gt;alert('xss')&lt;/script&gt;</RawXss>
  <IsActive>true</IsActive>
  <CreatedAt>2026-06-21T09:55:00Z</CreatedAt>
  <UnsafeNumber>9007199254740999</UnsafeNumber>
  <EmptyField></EmptyField>
</ApiResponse>`
};

class DashboardApp {
  constructor() {
    this.currentFormat = "json";
    this.activePage = "overview";
    this.cachedReport = null;
    this.cachedSecurityReport = null;

    this.initElements();
    this.initEventListeners();
    this.loadSampleData();
  }

  initElements() {
    // Nav Items
    this.navItems = document.querySelectorAll(".nav-item");
    this.pages = document.querySelectorAll(".page");
    this.pageTitleDisplay = document.getElementById("page-title-display");

    // Format buttons
    this.btnJSON = document.getElementById("toggle-json");
    this.btnXML = document.getElementById("toggle-xml");

    // Input textareas
    this.overviewRawInput = document.getElementById("overview-raw-input");
    this.diagRawInput = document.getElementById("diag-raw-input");
    this.secRawInput = document.getElementById("sec-raw-input");
    this.diffPayloadA = document.getElementById("diff-payload-a");
    this.diffPayloadB = document.getElementById("diff-payload-b");
    this.schemaPayloadInput = document.getElementById("schema-payload-input");
    this.schemaDefInput = document.getElementById("schema-def-input");

    // Overview Elements
    this.statTotalKeys = document.getElementById("stat-total-keys");
    this.statNestingDepth = document.getElementById("stat-nesting-depth");
    this.statSecurityIssues = document.getElementById("stat-security-issues");
    this.statHealthScore = document.getElementById("stat-health-score");
    this.overviewEmpty = document.getElementById("overview-empty-state");
    this.overviewResults = document.getElementById("overview-results-view");
    this.overviewWarnings = document.getElementById("overview-warnings-list");
    this.sumDominantStyle = document.getElementById("sum-dominant-style");
    this.sumStyleConsistency = document.getElementById("sum-style-consistency");
    this.charCounter = document.getElementById("editor-char-counter");

    // Diagnostics Page Elements
    this.diagEmpty = document.getElementById("diag-empty-state");
    this.diagResults = document.getElementById("diag-results-container");
    this.metricNulls = document.getElementById("metric-nulls");
    this.metricEmpty = document.getElementById("metric-empty");
    this.metricUnsafeFloats = document.getElementById("metric-unsafe-floats");
    this.namingBarChart = document.getElementById("naming-bar-chart");
    this.diagWarnings = document.getElementById("diag-warnings-container");

    // Security Page Elements
    this.secEmpty = document.getElementById("sec-empty-state");
    this.secResults = document.getElementById("sec-results-container");
    this.secStatusHeader = document.getElementById("sec-status-header");
    this.secFindingsList = document.getElementById("sec-findings-list");

    // Client Elements
    this.clientMethod = document.getElementById("client-method");
    this.clientUrl = document.getElementById("client-url");
    this.clientHeadersList = document.getElementById("client-headers-list");
    this.clientRawBody = document.getElementById("client-raw-body");
    this.clientEmpty = document.getElementById("client-empty-state");
    this.clientResults = document.getElementById("client-results-container");
    this.clientStatusContainer = document.getElementById("client-status-badge-container");
    this.respLatency = document.getElementById("resp-latency");
    this.respSize = document.getElementById("resp-size");
    this.respMime = document.getElementById("resp-mime");
    this.respBodyText = document.getElementById("resp-body-text");

    // Diff Elements
    this.diffEmpty = document.getElementById("diff-empty-state");
    this.diffResults = document.getElementById("diff-results-container");
    this.diffSumAdded = document.getElementById("diff-sum-added");
    this.diffSumDeleted = document.getElementById("diff-sum-deleted");
    this.diffSumModified = document.getElementById("diff-sum-modified");
    this.diffSumDrifted = document.getElementById("diff-sum-drifted");
    this.diffBreakdownList = document.getElementById("diff-breakdown-list");

    // Schema Elements
    this.schemaValResultCard = document.getElementById("schema-val-result-card");
    this.schemaValTitle = document.getElementById("schema-val-title");
    this.schemaValBox = document.getElementById("schema-val-box");
  }

  initEventListeners() {
    // Navigation Page switching
    this.navItems.forEach(item => {
      item.addEventListener("click", () => {
        const targetPage = item.getAttribute("data-page");
        this.switchPage(targetPage);
      });
    });

    // Format switches
    this.btnJSON.addEventListener("click", () => this.switchFormat("json"));
    this.btnXML.addEventListener("click", () => this.switchFormat("xml"));

    // Overview buttons
    document.getElementById("btn-load-sample").addEventListener("click", () => this.loadSampleData());
    document.getElementById("btn-overview-format").addEventListener("click", () => this.formatPayload("overview"));
    document.getElementById("btn-overview-minify").addEventListener("click", () => this.minifyPayload("overview"));
    document.getElementById("btn-overview-run").addEventListener("click", () => this.runOverviewDiagnostics());
    this.overviewRawInput.addEventListener("input", () => {
      this.charCounter.textContent = `${this.overviewRawInput.value.length} chars`;
    });

    // Diag buttons
    document.getElementById("btn-diag-format").addEventListener("click", () => this.formatPayload("diag"));
    document.getElementById("btn-diag-clear").addEventListener("click", () => { this.diagRawInput.value = ""; });
    document.getElementById("btn-diag-submit").addEventListener("click", () => this.runFullDiagnostics());

    // Security buttons
    document.getElementById("btn-sec-sample").addEventListener("click", () => {
      this.secRawInput.value = SAMPLES[this.currentFormat];
    });
    document.getElementById("btn-sec-scan").addEventListener("click", () => this.runSecurityScan());

    // Client buttons
    document.getElementById("btn-add-header").addEventListener("click", () => this.addHeaderRow());
    document.getElementById("btn-client-send").addEventListener("click", () => this.sendClientRequest());
    document.getElementById("btn-import-resp").addEventListener("click", () => this.importResponseToDiag());
    
    // Header removal delegations
    this.clientHeadersList.addEventListener("click", (e) => {
      if (e.target.closest(".btn-remove-header")) {
        e.target.closest(".header-row").remove();
      }
    });

    // Diff buttons
    document.getElementById("btn-compare-payloads").addEventListener("click", () => this.runComparison());

    // Schema buttons
    document.getElementById("btn-schema-load-sample").addEventListener("click", () => {
      this.schemaPayloadInput.value = SAMPLES[this.currentFormat];
    });
    document.getElementById("btn-generate-schema").addEventListener("click", () => this.generateSchema());
    document.getElementById("btn-run-validation").addEventListener("click", () => this.runSchemaValidation());
  }

  switchPage(pageId) {
    this.activePage = pageId;
    this.navItems.forEach(item => {
      if (item.getAttribute("data-page") === pageId) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    this.pages.forEach(p => {
      if (p.id === `page-${pageId}`) {
        p.classList.add("active");
      } else {
        p.classList.remove("active");
      }
    });

    // Synchronize content to target editors if they are empty
    this.syncInputEditors(pageId);

    // Update Top Header Display Name
    const pageTitles = {
      overview: "Dashboard Overview",
      diagnostics: "Diagnostics Suite",
      security: "Security Auditor",
      client: "REST Request Client",
      diff: "Payload Comparator",
      schema: "Schema Hub"
    };
    this.pageTitleDisplay.textContent = pageTitles[pageId] || "Dashboard";
  }

  switchFormat(format) {
    this.currentFormat = format;
    if (format === "json") {
      this.btnJSON.classList.add("active");
      this.btnXML.classList.remove("active");
    } else {
      this.btnXML.classList.add("active");
      this.btnJSON.classList.remove("active");
    }

    // Refresh sample in inputs that contain default values
    this.loadSampleData();
  }

  loadSampleData() {
    const val = SAMPLES[this.currentFormat];
    this.overviewRawInput.value = val;
    this.charCounter.textContent = `${val.length} chars`;

    // Also populate default secondary boxes if empty
    if (!this.diagRawInput.value) this.diagRawInput.value = val;
    if (!this.secRawInput.value) this.secRawInput.value = val;
    if (!this.schemaPayloadInput.value) this.schemaPayloadInput.value = val;
    
    // Set default schema
    if (this.currentFormat === "json") {
      this.schemaDefInput.placeholder = `{\n  "type": "object",\n  "properties": {\n    "api_version": { "type": "string" }\n  }\n}`;
      this.diffPayloadA.placeholder = `{\n  "status": "success",\n  "data": { "id": 100 }\n}`;
      this.diffPayloadB.placeholder = `{\n  "status": "success",\n  "data": { "id": 100, "role": "admin" }\n}`;
    } else {
      this.schemaDefInput.placeholder = `<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">\n  <!-- XSD Validation Definition -->\n</xs:schema>`;
      this.diffPayloadA.placeholder = `<ApiResponse>\n  <Id>100</Id>\n</ApiResponse>`;
      this.diffPayloadB.placeholder = `<ApiResponse>\n  <Id>100</Id>\n  <Role>Admin</Role>\n</ApiResponse>`;
    }
  }

  syncInputEditors(pageId) {
    const activeText = this.overviewRawInput.value;
    if (!activeText) return;

    if (pageId === "diagnostics" && !this.diagRawInput.value) {
      this.diagRawInput.value = activeText;
    } else if (pageId === "security" && !this.secRawInput.value) {
      this.secRawInput.value = activeText;
    } else if (pageId === "schema" && !this.schemaPayloadInput.value) {
      this.schemaPayloadInput.value = activeText;
    }
  }

  // API Call helper
  async postData(url, data) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      return await response.json();
    } catch (err) {
      console.error("API Fetch Error:", err);
      return { success: false, error: { message: "Failed to connect to FastAPI Backend server." } };
    }
  }

  // Validate & Format payload via backend formatter
  async formatPayload(editorKey) {
    const textarea = editorKey === "overview" ? this.overviewRawInput : this.diagRawInput;
    const rawVal = textarea.value;
    if (!rawVal.trim()) return;

    const res = await this.postData("/api/validate", {
      payload: rawVal,
      format_type: this.currentFormat
    });

    if (res.success) {
      textarea.value = res.formatted;
    } else {
      alert(`Formatting failed: ${res.error.message} (Line ${res.error.line}, Col ${res.error.column})`);
    }
  }

  // Quick Minify
  minifyPayload(editorKey) {
    const textarea = editorKey === "overview" ? this.overviewRawInput : this.diagRawInput;
    const rawVal = textarea.value;
    if (!rawVal.trim()) return;

    if (this.currentFormat === "json") {
      try {
        textarea.value = JSON.stringify(JSON.parse(rawVal));
      } catch (ex) {
        alert("Syntax Error: Unable to minify invalid JSON structure.");
      }
    } else {
      // Basic XML regex minify
      const minified = rawVal.replace(/>\s+</g, '><').trim();
      textarea.value = minified;
    }
  }

  // Dashboard Overview Analyzer
  async runOverviewDiagnostics() {
    const rawVal = this.overviewRawInput.value;
    if (!rawVal.trim()) {
      alert("Please paste a payload to analyze.");
      return;
    }

    // Call diagnostics
    const diagRes = await this.postData("/api/analyze", {
      payload: rawVal,
      format_type: this.currentFormat
    });

    // Call security
    const secRes = await this.postData("/api/scan", {
      payload: rawVal,
      format_type: this.currentFormat
    });

    if (!diagRes.success) {
      alert(`Diagnostics validation error: ${diagRes.error.message} (Line ${diagRes.error.line})`);
      return;
    }

    this.cachedReport = diagRes;
    this.cachedSecurityReport = secRes;

    // Render Stats Metrics
    this.statTotalKeys.textContent = diagRes.metrics.total_keys;
    this.statNestingDepth.textContent = diagRes.metrics.max_depth;
    this.statSecurityIssues.textContent = secRes.findings.length;
    
    // Calculate health score: start from 100. Deduct 15 per high/critical security issue, 5 per medium, 2 per warning.
    let score = 100;
    secRes.findings.forEach(f => {
      if (f.severity === "critical" || f.severity === "high") score -= 15;
      else if (f.severity === "medium") score -= 8;
      else score -= 3;
    });
    diagRes.warnings.forEach(() => { score -= 2; });
    score = Math.max(10, Math.min(100, score));

    this.statHealthScore.textContent = `${score}%`;
    
    const scoreColorMap = (s) => {
      if (s > 80) return "emerald";
      if (s > 50) return "amber";
      return "rose";
    };
    
    // Adjust Health Icon styling based on score
    const healthIcon = this.statHealthScore.closest(".stat-widget").querySelector(".stat-icon");
    healthIcon.className = `stat-icon ${scoreColorMap(score)}`;

    // Render summary sidebar
    this.overviewEmpty.style.display = "none";
    this.overviewResults.style.display = "block";
    this.sumDominantStyle.textContent = diagRes.metrics.dominant_naming_style;
    this.sumStyleConsistency.textContent = `${diagRes.metrics.naming_consistency_percent}%`;

    // Render small warnings table
    this.overviewWarnings.innerHTML = "";
    const allWarnings = [...diagRes.warnings];
    
    // Inject security issues as urgent warnings
    secRes.findings.forEach(f => {
      allWarnings.unshift({
        category: "Security",
        severity: f.severity,
        message: `${f.rule}: ${f.evidence}`
      });
    });

    if (allWarnings.length === 0) {
      this.overviewWarnings.innerHTML = `<div style="color: var(--success); font-size:0.85rem; padding: 0.5rem;"><i class="fa-solid fa-circle-check"></i> No warnings found. Payload is exceptionally clean!</div>`;
    } else {
      allWarnings.forEach(w => {
        const severityClass = w.severity === "high" || w.severity === "critical" ? "high" : "low";
        this.overviewWarnings.innerHTML += `
          <div class="warning-item ${severityClass}" style="padding: 0.5rem; margin-bottom: 0.5rem;">
            <i class="fa-solid fa-triangle-exclamation warning-icon ${w.severity}"></i>
            <div class="warning-details">
              <span class="warning-title" style="font-size: 0.8rem; text-transform: uppercase;">${w.category} [${w.severity}]</span>
              <span class="warning-message" style="font-size: 0.75rem;">${w.message}</span>
            </div>
          </div>
        `;
      });
    }
  }

  // Full Diagnostics suite runs
  async runFullDiagnostics() {
    const rawVal = this.diagRawInput.value;
    if (!rawVal.trim()) {
      alert("Please paste a payload to run checks.");
      return;
    }

    const res = await this.postData("/api/analyze", {
      payload: rawVal,
      format_type: this.currentFormat
    });

    if (!res.success) {
      alert(`Parser Error: ${res.error.message} at line ${res.error.line}`);
      return;
    }

    this.diagEmpty.style.display = "none";
    this.diagResults.style.display = "block";

    // Populate standard boxes
    this.metricNulls.textContent = res.metrics.null_values;
    this.metricEmpty.textContent = res.metrics.empty_structures;
    this.metricUnsafeFloats.textContent = res.metrics.unsafe_floats_count;

    // Build naming chart
    this.namingBarChart.innerHTML = "";
    const dist = res.metrics.naming_distribution;
    const total = Object.values(dist).reduce((a, b) => a + b, 0);

    for (const [style, count] of Object.entries(dist)) {
      const pct = total > 0 ? ((count / total) * 100).toFixed(0) : 0;
      this.namingBarChart.innerHTML += `
        <div class="naming-style-row">
          <span class="naming-style-label">${style}</span>
          <div class="naming-style-bar-bg">
            <div class="naming-style-bar-fill" style="width: ${pct}%"></div>
          </div>
          <span class="naming-style-val">${pct}%</span>
        </div>
      `;
    }

    // Render cleanliness warnings list
    this.diagWarnings.innerHTML = "";
    if (res.warnings.length === 0) {
      this.diagWarnings.innerHTML = `<div style="color: var(--success); font-size:0.9rem;"><i class="fa-solid fa-circle-check"></i> Code conventions, nesting depths, and floating constraints comply fully.</div>`;
    } else {
      res.warnings.forEach(w => {
        this.diagWarnings.innerHTML += `
          <div class="warning-item ${w.severity === 'medium' ? '' : 'high'}" style="margin-bottom:0.5rem; padding: 0.75rem;">
            <i class="fa-solid fa-circle-exclamation warning-icon ${w.severity}"></i>
            <div class="warning-details">
              <span class="warning-title">${w.category} Warning</span>
              <span class="warning-message">${w.message}</span>
            </div>
          </div>
        `;
      });
    }
  }

  // Security Scanner audits
  async runSecurityScan() {
    const rawVal = this.secRawInput.value;
    if (!rawVal.trim()) {
      alert("Please paste a payload to scan.");
      return;
    }

    const res = await this.postData("/api/scan", {
      payload: rawVal,
      format_type: this.currentFormat
    });

    if (!res.success) {
      alert("Security audit failed. Invalid parser state.");
      return;
    }

    this.secEmpty.style.display = "none";
    this.secResults.style.display = "block";

    // Setup Status Header UI
    this.secStatusHeader.innerHTML = "";
    if (res.vulnerable) {
      const color = res.critical_count > 0 ? "rgba(217, 70, 239, 0.15)" : "rgba(244, 63, 94, 0.15)";
      const text = res.critical_count > 0 ? `${res.critical_count} CRITICAL Risk Threats Discovered` : `${res.findings.length} Vulnerabilities Detected`;
      const icon = res.critical_count > 0 ? "fa-circle-radiation" : "fa-shield-virus";
      const border = res.critical_count > 0 ? "1px solid var(--critical)" : "1px solid var(--danger)";
      
      this.secStatusHeader.style.background = color;
      this.secStatusHeader.style.border = border;
      this.secStatusHeader.innerHTML = `
        <i class="fa-solid ${icon}" style="font-size: 1.5rem; color: ${res.critical_count > 0 ? 'var(--critical)' : 'var(--danger)'}"></i>
        <div>
          <div style="font-size: 1rem; color: #fff;">${text}</div>
          <div style="font-size: 0.8rem; font-weight: normal; color: var(--text-muted); margin-top:0.15rem;">Review detailed credentials, PII leakage, and SQL/XSS reports below.</div>
        </div>
      `;
    } else {
      this.secStatusHeader.style.background = "rgba(16, 185, 129, 0.15)";
      this.secStatusHeader.style.border = "1px solid var(--success)";
      this.secStatusHeader.innerHTML = `
        <i class="fa-solid fa-circle-check" style="font-size: 1.5rem; color: var(--success)"></i>
        <div>
          <div style="font-size: 1rem; color: #fff;">No Sensitive Exploits Found</div>
          <div style="font-size: 0.8rem; font-weight: normal; color: var(--text-muted); margin-top:0.15rem;">Payload scanner detected no credentials, SQL strings, XSS scripts, or XXE threats.</div>
        </div>
      `;
    }

    // Render Findings List
    this.secFindingsList.innerHTML = "";
    if (res.findings.length === 0) {
      this.secFindingsList.innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
          <i class="fa-solid fa-thumbs-up" style="font-size: 1.5rem; margin-bottom: 0.5rem; color: var(--success);"></i>
          <p>Scanner audit is clean.</p>
        </div>
      `;
    } else {
      res.findings.forEach(f => {
        this.secFindingsList.innerHTML += `
          <div class="warning-item ${f.severity === 'medium' ? '' : (f.severity === 'low' ? 'low' : 'critical')}" style="margin-bottom:0.75rem;">
            <i class="fa-solid fa-triangle-exclamation warning-icon ${f.severity}"></i>
            <div class="warning-details" style="width: 100%;">
              <span class="warning-title" style="display:flex; justify-content:space-between; width: 100%;">
                <span>${f.rule}</span>
                <span style="font-size:0.75rem; text-transform:uppercase; color: var(--text-muted);">${f.severity} severity</span>
              </span>
              <span class="warning-message">${f.description}</span>
              <div class="warning-evidence">Matched Evidence: "${f.evidence}"</div>
            </div>
          </div>
        `;
      });
    }
  }

  // REST API Client Proxy
  addHeaderRow() {
    const row = document.createElement("div");
    row.className = "header-row";
    row.innerHTML = `
      <input type="text" placeholder="Header-Key" class="header-key">
      <input type="text" placeholder="Header-Value" class="header-value">
      <button class="btn btn-secondary btn-sm btn-danger btn-remove-header" style="padding: 0.5rem;"><i class="fa-solid fa-trash"></i></button>
    `;
    this.clientHeadersList.appendChild(row);
  }

  async sendClientRequest() {
    const method = this.clientMethod.value;
    const url = this.clientUrl.value.trim();
    if (!url) {
      alert("Please specify a request URL.");
      return;
    }

    // Assemble headers
    const headers = {};
    const keyInputs = this.clientHeadersList.querySelectorAll(".header-key");
    const valInputs = this.clientHeadersList.querySelectorAll(".header-value");
    
    for (let i = 0; i < keyInputs.length; i++) {
      const k = keyInputs[i].value.trim();
      const v = valInputs[i].value.trim();
      if (k && v) {
        headers[k] = v;
      }
    }

    const bodyVal = this.clientRawBody.value;

    this.clientEmpty.style.display = "none";
    this.clientResults.style.display = "none";
    
    // Show Loading state
    const originalBtnText = document.getElementById("btn-client-send").innerHTML;
    document.getElementById("btn-client-send").innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Executing...`;
    document.getElementById("btn-client-send").disabled = true;

    const res = await this.postData("/api/client/request", {
      method: method,
      url: url,
      headers: headers,
      body: bodyVal ? bodyVal : null
    });

    document.getElementById("btn-client-send").innerHTML = originalBtnText;
    document.getElementById("btn-client-send").disabled = false;

    this.clientResults.style.display = "block";

    if (!res.success) {
      this.clientStatusContainer.innerHTML = `<span class="status-badge s5xx">FAIL</span>`;
      this.respLatency.textContent = `${res.latency_ms} ms`;
      this.respSize.textContent = "0 B";
      this.respMime.textContent = "N/A";
      this.respBodyText.textContent = res.error || "A connection runtime error occurred.";
      return;
    }

    // Render Status Badges
    const status = res.status_code;
    let badgeClass = "s2xx";
    if (status >= 300 && status < 400) badgeClass = "s3xx";
    else if (status >= 400 && status < 500) badgeClass = "s4xx";
    else if (status >= 500) badgeClass = "s5xx";

    this.clientStatusContainer.innerHTML = `<span class="status-badge ${badgeClass}">${status}</span>`;
    
    // Performance
    this.respLatency.textContent = `${res.latency_ms} ms`;
    
    // Size converter
    const size = res.size_bytes;
    this.respSize.textContent = size > 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`;
    
    // MIME type display
    const typeArr = res.content_type.split(";");
    this.respMime.textContent = typeArr[0];

    // Response content text
    this.respBodyText.textContent = res.body;
  }

  importResponseToDiag() {
    const text = this.respBodyText.textContent;
    if (!text || text.startsWith("HTTP Request failed")) {
      alert("No valid response body to import.");
      return;
    }

    // Set structure type check
    const isXml = text.trim().startsWith("<");
    this.switchFormat(isXml ? "xml" : "json");

    this.diagRawInput.value = text;
    this.switchPage("diagnostics");
    this.runFullDiagnostics();
  }

  // Payload diff comparator
  async runComparison() {
    const a = this.diffPayloadA.value;
    const b = this.diffPayloadB.value;
    if (!a.trim() || !b.trim()) {
      alert("Please specify both payloads to run differences.");
      return;
    }

    const res = await this.postData("/api/diff", {
      payload_a: a,
      payload_b: b,
      format_type: this.currentFormat
    });

    if (!res.success) {
      alert(`Diff failed: ${res.error}`);
      return;
    }

    this.diffEmpty.style.display = "none";
    this.diffResults.style.display = "block";

    // Update diff counts
    this.diffSumAdded.textContent = res.summary.added_count;
    this.diffSumDeleted.textContent = res.summary.deleted_count;
    this.diffSumModified.textContent = res.summary.modified_count;
    this.diffSumDrifted.textContent = res.summary.drifted_count;

    // Render list
    this.diffBreakdownList.innerHTML = "";
    let hasDiff = false;

    // Added elements
    for (const [path, meta] of Object.entries(res.diffs.added)) {
      hasDiff = true;
      const displayVal = typeof meta.value === "object" ? JSON.stringify(meta.value) : meta.value;
      this.diffBreakdownList.innerHTML += `
        <div class="diff-item added">
          <span class="diff-type added"><i class="fa-solid fa-plus-circle"></i> Added Path</span>
          <div class="diff-desc">
            <span class="diff-path">${path}</span>
            <span class="diff-vals">Type: <span class="highlight">${meta.type}</span>, Value: <span class="highlight">${displayVal}</span></span>
          </div>
        </div>
      `;
    }

    // Deleted elements
    for (const [path, meta] of Object.entries(res.diffs.deleted)) {
      hasDiff = true;
      const displayVal = typeof meta.value === "object" ? JSON.stringify(meta.value) : meta.value;
      this.diffBreakdownList.innerHTML += `
        <div class="diff-item deleted">
          <span class="diff-type deleted"><i class="fa-solid fa-minus-circle"></i> Deleted Path</span>
          <div class="diff-desc">
            <span class="diff-path">${path}</span>
            <span class="diff-vals">Type: <span class="highlight">${meta.type}</span>, Previous Value: <span class="highlight">${displayVal}</span></span>
          </div>
        </div>
      `;
    }

    // Modified elements
    for (const [path, meta] of Object.entries(res.diffs.modified)) {
      hasDiff = true;
      this.diffBreakdownList.innerHTML += `
        <div class="diff-item modified">
          <span class="diff-type modified"><i class="fa-solid fa-pen-to-square"></i> Modified Value</span>
          <div class="diff-desc">
            <span class="diff-path">${path}</span>
            <span class="diff-vals">Value changed from <span class="highlight">${meta.old_value}</span> to <span class="highlight">${meta.new_value}</span></span>
          </div>
        </div>
      `;
    }

    // Schema Type drifted elements
    for (const [path, meta] of Object.entries(res.diffs.drifted)) {
      hasDiff = true;
      this.diffBreakdownList.innerHTML += `
        <div class="diff-item drifted">
          <span class="diff-type drifted"><i class="fa-solid fa-circle-nodes"></i> Schema Type Drift</span>
          <div class="diff-desc">
            <span class="diff-path">${path}</span>
            <span class="diff-vals">Type drifted from <span class="highlight">${meta.old_type}</span> to <span class="highlight">${meta.new_type}</span> (value: <span class="highlight">${meta.new_value}</span>)</span>
          </div>
        </div>
      `;
    }

    if (!hasDiff) {
      this.diffBreakdownList.innerHTML = `<div style="text-align: center; color: var(--success); padding: 1rem;"><i class="fa-solid fa-circle-check"></i> Both structures match identically. No drift detected.</div>`;
    }
  }

  // Schema Hub Generator
  async generateSchema() {
    const rawVal = this.schemaPayloadInput.value;
    if (!rawVal.trim()) {
      alert("Please paste a data payload.");
      return;
    }

    const res = await this.postData("/api/schema/generate", {
      payload: rawVal,
      format_type: this.currentFormat
    });

    if (!res.success) {
      alert(`Failed to infer schema: ${res.error.message}`);
      return;
    }

    // Format output
    if (res.type === "json-schema") {
      this.schemaDefInput.value = JSON.stringify(res.schema, null, 2);
    } else {
      // For XML trees, print structural map representation
      this.schemaDefInput.value = JSON.stringify(res.schema, null, 2);
    }
  }

  // Schema Validator runs
  async runSchemaValidation() {
    const rawVal = this.schemaPayloadInput.value;
    const schemaDef = this.schemaDefInput.value;

    if (!rawVal.trim() || !schemaDef.trim()) {
      alert("Please specify both the payload data and schema definition.");
      return;
    }

    this.schemaValResultCard.style.display = "block";
    this.schemaValBox.className = "schema-val-box";
    this.schemaValBox.innerHTML = `<span><i class="fa-solid fa-spinner fa-spin"></i> Performing validation...</span>`;

    const res = await this.postData("/api/schema/validate", {
      payload: rawVal,
      schema_definition: schemaDef,
      format_type: this.currentFormat
    });

    if (res.success) {
      this.schemaValBox.style.background = "rgba(16, 185, 129, 0.15)";
      this.schemaValBox.style.border = "1px solid var(--success)";
      this.schemaValBox.style.color = "var(--success)";
      this.schemaValBox.innerHTML = `<i class="fa-solid fa-circle-check"></i> <span>Success: Payload corresponds fully to the specified Schema definition constraints.</span>`;
    } else {
      this.schemaValBox.style.background = "rgba(244, 63, 94, 0.15)";
      this.schemaValBox.style.border = "1px solid var(--danger)";
      this.schemaValBox.style.color = "var(--danger)";
      
      let errMsg = "";
      res.errors.forEach(e => {
        errMsg += `<div><strong>Error:</strong> ${e.message} ${e.context ? '(' + e.context + ')' : ''} (Line ${e.line})</div>`;
      });
      this.schemaValBox.innerHTML = `<i class="fa-solid fa-circle-xmark" style="font-size:1.25rem; margin-top:0.25rem;"></i> <div style="display:flex; flex-direction:column; gap:0.25rem;">${errMsg}</div>`;
    }
  }
}

// Instantiate App
document.addEventListener("DOMContentLoaded", () => {
  window.app = new DashboardApp();
});
