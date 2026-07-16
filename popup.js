function levelClass(level) {
  return level === "high" ? "high" : level === "medium" ? "medium" : "low";
}

function render(report) {
  const el = document.getElementById("report");
  if (!report || !report.privacyRiskScore === null) {
    el.innerHTML = "<p>No data yet — try re-scanning.</p>";
    return;
  }

  const score = report.privacyRiskScore ?? "…";
  const level = report.riskLevel || "low";

  let html = `
    <section>
      <div class="score ${levelClass(level)}">${score}/100</div>
      <div>Privacy/Security Risk — <span class="tag">${level}</span></div>
    </section>
  `;

  if (report.urlHeuristics) {
    html += `<section><strong>URL Heuristics</strong> (${report.urlHeuristics.score}/100, ${report.urlHeuristics.level})<ul>`;
    for (const t of report.urlHeuristics.triggered) html += `<li>${t.reason}</li>`;
    if (!report.urlHeuristics.triggered.length) html += `<li>No suspicious patterns found</li>`;
    html += `</ul></section>`;
  }

  if (report.securityAudit) {
    const sa = report.securityAudit;
    html += `<section><strong>Security Headers</strong> (${sa.headerScore}/100)<ul>`;
    html += `<li>HTTPS: ${sa.isHttps ? "Yes" : "No"}</li>`;
    if (sa.tlsSupported && sa.tlsInfo) {
      html += `<li>TLS state: ${sa.tlsInfo.state}, ${sa.tlsInfo.protocolVersion}</li>`;
    } else {
      html += `<li>TLS certificate details aren't exposed to extensions in this browser</li>`;
    }
    for (const m of sa.missing) html += `<li>Missing: ${m.label}</li>`;
    html += `</ul></section>`;
  }

  if (report.trackerMap) {
    const tm = report.trackerMap;
    html += `<section><strong>Trackers & Cookies</strong><ul>`;
    html += `<li>Third-party domains contacted: ${tm.thirdPartyRequestCount}</li>`;
    html += `<li>Known trackers detected: ${tm.knownTrackerCount}</li>`;
    html += `<li>Third-party cookies: ${tm.thirdPartyCookieCount}</li>`;
    html += `</ul></section>`;
  }

  if (report.threatIntel) {
    const ti = report.threatIntel;
    html += `<section><strong>Threat Intel</strong><ul>`;
    if (ti.checked) {
      html += `<li>Verdict: ${ti.verdict} (${ti.malicious}/${ti.totalEngines} engines flagged)</li>`;
    } else {
      html += `<li>${ti.reason}</li>`;
    }
    html += `</ul></section>`;
  }

  el.innerHTML = html;
}

function loadReport() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0]?.id;
    if (tabId == null) return;
    chrome.runtime.sendMessage({ type: "GET_REPORT", tabId }, render);
  });
}

document.getElementById("rescan").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabId = tabs[0]?.id;
    if (tabId == null) return;
    chrome.runtime.sendMessage({ type: "RESCAN", tabId }, () => {
      setTimeout(loadReport, 2000);
    });
  });
});

loadReport();
