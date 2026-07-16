/**
 * SiteGuard — background.js (Manifest V3 service worker)
 * ---------------------------------------------------------------
 * Four modules, each exposed as its own function so they can be
 * unit-tested or called independently from the popup:
 *
 *   1. analyzeUrlHeuristics(url)        -> phishing pattern score
 *   2. auditSecurity(url)               -> headers + TLS-adjacent signals
 *   3. TrackerMapper (class)            -> live third-party request/cookie tally
 *   4. checkThreatIntel(domain, apiKey) -> VirusTotal domain reputation
 *
 * All four feed a combined "risk report" per tab, cached in memory
 * and pushed to the popup on request.
 * ---------------------------------------------------------------
 */

// =================================================================
// Shared state: one report object per tabId
// =================================================================
const tabReports = new Map();

function getReport(tabId) {
  if (!tabReports.has(tabId)) {
    tabReports.set(tabId, {
      url: null,
      urlHeuristics: null,
      securityAudit: null,
      trackerMap: null,
      threatIntel: null,
      privacyRiskScore: null,
      lastUpdated: null,
    });
  }
  return tabReports.get(tabId);
}

// =================================================================
// MODULE 1 — Active URL Heuristic Analyzer
// =================================================================

// Small, easily-extended rule set. Each rule returns a weight (0-100
// contribution) and a human-readable reason when it fires.
const URL_HEURISTIC_RULES = [
  {
    id: "ip_literal_host",
    weight: 30,
    test: (u) => /^(\d{1,3}\.){3}\d{1,3}$/.test(u.hostname),
    reason: "Host is a raw IP address instead of a domain name",
  },
  {
    id: "punycode_domain",
    weight: 25,
    test: (u) => u.hostname.includes("xn--"),
    reason: "Domain uses punycode (possible homograph/lookalike attack)",
  },
  {
    id: "excessive_subdomains",
    weight: 15,
    test: (u) => u.hostname.split(".").length >= 5,
    reason: "Unusually many subdomain levels",
  },
  {
    id: "at_symbol_in_url",
    weight: 25,
    test: (u) => u.href.includes("@") && u.href.indexOf("@") < u.href.indexOf(u.hostname) + u.hostname.length + 20,
    reason: "URL contains an '@' which can hide the real destination",
  },
  {
    id: "many_hyphens",
    weight: 10,
    test: (u) => (u.hostname.match(/-/g) || []).length >= 3,
    reason: "Domain contains an unusually high number of hyphens",
  },
  {
    id: "suspicious_tld",
    weight: 15,
    // Non-exhaustive list of TLDs commonly abused in phishing campaigns
    test: (u) => /\.(zip|mov|xyz|top|tk|gq|ml|cf|work|click|country)$/i.test(u.hostname),
    reason: "Top-level domain is one frequently abused for phishing",
  },
  {
    id: "brand_keyword_mismatch",
    weight: 35,
    test: (u) => {
      const brands = ["paypal", "microsoft", "apple", "google", "amazon", "netflix", "bankofamerica", "chase", "wellsfargo"];
      const host = u.hostname.toLowerCase();
      return brands.some((b) => host.includes(b)) && !brands.some((b) => host === b + ".com" || host.endsWith("." + b + ".com"));
    },
    reason: "Domain references a well-known brand but isn't that brand's real domain",
  },
  {
    id: "url_shortener",
    weight: 10,
    test: (u) => /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|buff\.ly)$/i.test(u.hostname),
    reason: "URL shortener — real destination is hidden",
  },
  {
    id: "insecure_scheme",
    weight: 20,
    test: (u) => u.protocol === "http:",
    reason: "Site is served over plain HTTP, not HTTPS",
  },
  {
    id: "encoded_chars_in_path",
    weight: 10,
    test: (u) => (u.pathname.match(/%[0-9a-f]{2}/gi) || []).length >= 4,
    reason: "Path contains heavy percent-encoding, often used to obscure content",
  },
  {
    id: "login_keyword_non_https",
    weight: 20,
    test: (u) => /login|signin|secure|verify|account|update/i.test(u.pathname) && u.protocol === "http:",
    reason: "Page path suggests a login/verification flow but isn't HTTPS",
  },
];

function analyzeUrlHeuristics(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    return { score: 0, level: "unknown", triggered: [], error: "Invalid URL" };
  }

  // Only meaningful for web pages
  if (!["http:", "https:"].includes(url.protocol)) {
    return { score: 0, level: "n/a", triggered: [] };
  }

  const triggered = [];
  let score = 0;
  for (const rule of URL_HEURISTIC_RULES) {
    try {
      if (rule.test(url)) {
        score += rule.weight;
        triggered.push({ id: rule.id, reason: rule.reason, weight: rule.weight });
      }
    } catch (e) {
      // A single bad rule shouldn't break analysis
      console.warn(`SiteGuard: heuristic rule ${rule.id} threw`, e);
    }
  }

  score = Math.min(100, score);
  const level = score >= 60 ? "high" : score >= 30 ? "medium" : score > 0 ? "low" : "none";

  return { score, level, triggered };
}

// =================================================================
// MODULE 2 — Security Header & SSL Auditor
// =================================================================

// NOTE ON PLATFORM LIMITS:
// Extension JavaScript cannot read raw TLS certificate fields
// (issuer, validity dates, cipher suite, chain) in Chrome — that API
// simply isn't exposed to extensions for security/privacy reasons.
// Firefox exposes *some* of this via webRequest.getSecurityInfo(),
// which we use when available and fall back gracefully otherwise.
const HEADER_CHECKS = [
  {
    header: "content-security-policy",
    label: "Content-Security-Policy",
    weight: 20,
    advice: "Mitigates XSS/data-injection by restricting allowed content sources.",
  },
  {
    header: "strict-transport-security",
    label: "Strict-Transport-Security (HSTS)",
    weight: 20,
    advice: "Forces browsers to only ever connect over HTTPS.",
  },
  {
    header: "x-frame-options",
    label: "X-Frame-Options",
    weight: 10,
    advice: "Prevents clickjacking via iframe embedding.",
  },
  {
    header: "x-content-type-options",
    label: "X-Content-Type-Options",
    weight: 10,
    advice: "Prevents MIME-sniffing attacks.",
  },
  {
    header: "referrer-policy",
    label: "Referrer-Policy",
    weight: 10,
    advice: "Controls how much URL data leaks to third parties on navigation.",
  },
  {
    header: "permissions-policy",
    label: "Permissions-Policy",
    weight: 10,
    advice: "Restricts access to sensitive browser features (camera, geo, etc).",
  },
];

async function auditSecurity(urlString) {
  const result = {
    isHttps: false,
    headers: {},
    missing: [],
    headerScore: 0, // 0 (bad) - 100 (great)
    tlsInfo: null,
    tlsSupported: false,
  };

  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    return { ...result, error: "Invalid URL" };
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    return { ...result, error: "Not a web page" };
  }

  result.isHttps = url.protocol === "https:";

  try {
    // 'no-cors' would hide headers, so we do a normal fetch. This can
    // fail for pages with restrictive CORS — that's fine, we just
    // report what we can. HEAD keeps it lightweight.
    const resp = await fetch(url.href, { method: "GET", redirect: "follow", cache: "no-store" });
    let earnedWeight = 0;
    let totalWeight = 0;

    for (const check of HEADER_CHECKS) {
      totalWeight += check.weight;
      const value = resp.headers.get(check.header);
      if (value) {
        result.headers[check.header] = value;
        earnedWeight += check.weight;
      } else {
        result.missing.push({ label: check.label, advice: check.advice });
      }
    }
    result.headerScore = totalWeight ? Math.round((earnedWeight / totalWeight) * 100) : 0;
  } catch (err) {
    result.error = `Could not fetch headers (likely CORS-restricted): ${err.message}`;
  }

  return result;
}

// Firefox-only: pull whatever connection security info the browser
// will hand over. On Chrome, browser.webRequest.getSecurityInfo does
// not exist, so tlsSupported stays false and the UI should say so
// plainly rather than fabricate cert data.
function tryAttachTlsInfo(details, tabId) {
  if (typeof browser === "undefined" || !browser.webRequest || !browser.webRequest.getSecurityInfo) {
    return; // Chrome / not supported
  }
  browser.webRequest
    .getSecurityInfo(details.requestId, { certificateChain: true })
    .then((secInfo) => {
      const report = getReport(tabId);
      if (!report.securityAudit) return;
      report.securityAudit.tlsSupported = true;
      report.securityAudit.tlsInfo = {
        state: secInfo.state, // "secure" | "insecure" | "broken"
        protocolVersion: secInfo.protocolVersion,
        cipherSuite: secInfo.cipherSuite,
        certIssuer: secInfo.certificates?.[0]?.issuer,
        certValidFrom: secInfo.certificates?.[0]?.validity?.start,
        certValidTo: secInfo.certificates?.[0]?.validity?.end,
      };
    })
    .catch(() => {
      /* best-effort only */
    });
}

// =================================================================
// MODULE 3 — Third-Party Tracker & Cookie Mapper
// =================================================================

// A small illustrative tracker-domain list. In production this
// should be swapped for a maintained list such as EasyList/EasyPrivacy
// or Disconnect.me's tracker JSON, fetched periodically and cached.
const KNOWN_TRACKER_DOMAINS = [
  "google-analytics.com", "googletagmanager.com", "doubleclick.net",
  "facebook.net", "facebook.com", "connect.facebook.net",
  "adsystem.amazon.com", "amazon-adsystem.com",
  "hotjar.com", "segment.io", "mixpanel.com", "scorecardresearch.com",
  "criteo.com", "taboola.com", "outbrain.com", "adroll.com",
  "quantserve.com", "moatads.com", "bing.com/bat.js",
];

function registrableDomain(hostname) {
  // Very small approximation of eTLD+1
  // use — a production build should use the Public Suffix List).
  const parts = hostname.split(".");
  return parts.length <= 2 ? hostname : parts.slice(-2).join(".");
}

function isKnownTracker(hostname) {
  return KNOWN_TRACKER_DOMAINS.some((d) => hostname.endsWith(d));
}

class TrackerMapper {
  constructor(tabId, pageUrl) {
    this.tabId = tabId;
    this.pageDomain = registrableDomain(new URL(pageUrl).hostname);
    this.thirdPartyRequestDomains = new Set();
    this.knownTrackerHits = new Set();
    this.thirdPartyCookieDomains = new Set();
  }

  // Call from webRequest.onBeforeRequest
  recordRequest(requestUrl) {
    try {
      const host = new URL(requestUrl).hostname;
      const domain = registrableDomain(host);
      if (domain !== this.pageDomain) {
        this.thirdPartyRequestDomains.add(domain);
        if (isKnownTracker(host)) this.knownTrackerHits.add(host);
      }
    } catch (e) {
      /* ignore malformed URLs */
    }
  }

  async scanCookies() {
    // chrome.cookies.getAll requires the "cookies" permission and
    // matching host permissions; we scan by the page's top domain.
    return new Promise((resolve) => {
      chrome.cookies.getAll({}, (cookies) => {
        this.thirdPartyCookieDomains.clear();
        for (const c of cookies) {
          const cookieDomain = c.domain.replace(/^\./, "");
          const reg = registrableDomain(cookieDomain);
          if (reg !== this.pageDomain) {
            this.thirdPartyCookieDomains.add(reg);
          }
        }
        resolve(this.summary());
      });
    });
  }

  summary() {
    return {
      thirdPartyRequestCount: this.thirdPartyRequestDomains.size,
      thirdPartyDomains: [...this.thirdPartyRequestDomains],
      knownTrackerCount: this.knownTrackerHits.size,
      knownTrackers: [...this.knownTrackerHits],
      thirdPartyCookieCount: this.thirdPartyCookieDomains.size,
      thirdPartyCookieDomains: [...this.thirdPartyCookieDomains],
    };
  }
}

const trackerMappers = new Map(); // tabId -> TrackerMapper

// =================================================================
// MODULE 4 — Threat Intel API Integration (VirusTotal)
// =================================================================

// The user must supply their own free VirusTotal API key via the
// options page (stored in chrome.storage.local). We never ship a
// key in source, and we never send more than the bare domain.
async function checkThreatIntel(domain) {
  const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
  if (!vtApiKey) {
    return { checked: false, reason: "No VirusTotal API key configured (see Options)." };
  }

  try {
    const resp = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      method: "GET",
      headers: { "x-apikey": vtApiKey },
    });

    if (resp.status === 429) {
      return { checked: false, reason: "VirusTotal rate limit hit (free tier: 4 req/min)." };
    }
    if (!resp.ok) {
      return { checked: false, reason: `VirusTotal returned HTTP ${resp.status}` };
    }

    const data = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0) || 1;

    return {
      checked: true,
      malicious,
      suspicious,
      harmless: stats.harmless || 0,
      totalEngines,
      verdict: malicious > 0 ? "flagged_malicious" : suspicious > 0 ? "flagged_suspicious" : "clean",
      reputation: data?.data?.attributes?.reputation ?? null,
    };
  } catch (err) {
    return { checked: false, reason: `Network error contacting VirusTotal: ${err.message}` };
  }
}

// =================================================================
// Combined risk scoring
// =================================================================

function computePrivacyRiskScore(report) {
  let score = 0;
  if (report.urlHeuristics) score += report.urlHeuristics.score * 0.35;
  if (report.securityAudit) score += (100 - report.securityAudit.headerScore) * 0.25;
  if (report.trackerMap) {
    score += Math.min(100, report.trackerMap.thirdPartyRequestCount * 5) * 0.2;
    score += Math.min(100, report.trackerMap.knownTrackerCount * 15) * 0.1;
  }
  if (report.threatIntel?.checked) {
    if (report.threatIntel.verdict === "flagged_malicious") score += 100 * 0.1;
    else if (report.threatIntel.verdict === "flagged_suspicious") score += 50 * 0.1;
  }
  score = Math.round(Math.min(100, score));
  const level = score >= 70 ? "high" : score >= 40 ? "medium" : "low";
  return { score, level };
}

// =================================================================
// Orchestration: run the full scan whenever a tab finishes loading
// =================================================================

async function runFullScan(tabId, url) {
  if (!url || !/^https?:\/\//.test(url)) return;

  const report = getReport(tabId);
  report.url = url;

  const mapper = new TrackerMapper(tabId, url);
  trackerMappers.set(tabId, mapper);

  const [urlHeuristics, securityAudit] = await Promise.all([
    Promise.resolve(analyzeUrlHeuristics(url)),
    auditSecurity(url),
  ]);

  report.urlHeuristics = urlHeuristics;
  report.securityAudit = securityAudit;

  // Give in-flight requests a moment to be captured by webRequest,
  // then snapshot cookies.
  setTimeout(async () => {
    report.trackerMap = await mapper.scanCookies();

    const domain = new URL(url).hostname;
    report.threatIntel = await checkThreatIntel(domain);

    const risk = computePrivacyRiskScore(report);
    report.privacyRiskScore = risk.score;
    report.riskLevel = risk.level;
    report.lastUpdated = Date.now();

    // Push a badge update so the risk is visible at a glance
    chrome.action.setBadgeText({ tabId, text: String(risk.score) });
    chrome.action.setBadgeBackgroundColor({
      tabId,
      color: risk.level === "high" ? "#d93025" : risk.level === "medium" ? "#f9ab00" : "#188038",
    });
  }, 1500);
}

// =================================================================
// Event wiring
// =================================================================

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const mapper = trackerMappers.get(details.tabId);
    if (mapper) mapper.recordRequest(details.url);
    tryAttachTlsInfo(details, details.tabId);
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    runFullScan(tabId, tab.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabReports.delete(tabId);
  trackerMappers.delete(tabId);
});

// Popup / options communication
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_REPORT") {
    const tabId = msg.tabId;
    sendResponse(tabReports.get(tabId) || null);
    return true;
  }
  if (msg.type === "RESCAN") {
    chrome.tabs.get(msg.tabId, (tab) => {
      if (tab?.url) runFullScan(msg.tabId, tab.url);
    });
    return true;
  }
});
