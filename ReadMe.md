# 🛡️ Sentinel: Threat Scan & Privacy Auditor

Sentinel is a lightweight, high-performance Manifest V3 Chrome Extension that audits web page security in real-time. It runs immediate, client-side heuristic phishing analyses, inspects HTTP response security headers, measures tracking cookie footprint, and checks domains against global blocklists.

---

**1. URL Heuristic Analyser ** (`analyzeUrlHeuristics`) — regex/pattern checks
against the active tab's URL: IP-literal hosts, punycode, excessive
subdomains, brand-name/domain mismatches, suspicious TLDs, `http:` on
login-looking paths, etc. Fully client-side, no network calls, easy to
extend by adding entries to `URL_HEURISTIC_RULES`.

**2. Security Header & SSL Auditor** (`auditSecurity`) — fetches the page and
inspects response headers (CSP, HSTS, X-Frame-Options, etc.) to produce a
header score. **Important limitation:** browser extension APIs do not expose
raw TLS certificate fields (issuer, expiry, cypher suite) to JavaScript —
this is a deliberate browser security boundary, not a gap in this code. On
Firefox, `webRequest.getSecurityInfo` provides some connection-level data
(protocol version, cypher, and certificate metadata) and the code uses it
when available; on Chrome there is no equivalent API, so the popup says so
explicitly rather than fabricating cert data.

**3. Tracker & Cookie Mapper** (`TrackerMapper`) — uses `webRequest` to see
every request the page triggers, flags third-party (different registrable
domain) requests, cross-references a small known-tracker list, and uses
`chrome.cookies.getAll` to count third-party cookies. The bundled tracker
list is illustrative only — swap it for a maintained list (e.g. Disconnect.me
or EasyList/EasyPrivacy, fetched and cached periodically) for real coverage.

**4. Threat Intel (VirusTotal)** — looks up the domain's reputation via
VirusTotal's free `/domains/{domain}` endpoint. You must supply your own
API key via Options; none is bundled. Only the bare domain is ever sent —
not the full URL, page content, or cookies. Free tier is rate-limited
(4 req/min, 500/day), so cache results per-domain in production rather than
calling on every navigation.

---

## Permission rationale (for store review/user trust)
- `webRequest` + `<all_urls>` — required to observe third-party requests.
- `cookies` — required to enumerate cookie domains for the privacy score.
- `storage` — stores only your VT API key locally, never synced.
- No analytics, no remote code, no data leaves the browser except the
  domain-only VirusTotal lookup you opt into.

---

## Known gaps / next steps
- Tracker list should be swapped for a real, updated blocklist.
- `registrableDomain()` is a naive eTLD+1 approximation; use the Public
  Suffix List for domains like `co.uk`.
- Consider caching VT/domain results (e.g. in `chrome.storage.local`) keyed
  by domain + day, to stay under free-tier rate limits.
- Icons in `/icons` are placeholder solid squares — swap in real artwork.

---

##  Tech Stack & Architecture

* **Manifest V3 Standard** (Fully Chrome compliant)
* **Service Workers** (Asynchronous background event handling API validation)
* **Vanilla JS, HTML5 & Modern CSS3** (With custom responsive security-dashboard styling)

---

## How to Install & Load Locally

1. Clone this repository to your computer:
   ```bash
   git clone [https://github.com/hanyamursaleen-spec/sentinel-threat-scanner.git](https://github.com/hanyamursaleen-spec/sentinel-threat-scanner.git)
   ```
2. Navigate to `chrome://extensions/` in Google Chrome.
3. Turn on **Developer Mode** (top-right toggle switch).
4. Click **Load unpacked** in the top-left menu.
5. Select folder: Sentinel-Threat-Scan-Privacy-Auditor.

---

## Testing Guidelines

For robust evaluation of your Sentinel dashboard, test it against these environments:
* **Normal Web:** Visit `https://github.com` — Expect high security header scores, clean indicators, and active HTTPS validation.
* **Phishing Heuristics Test:** Open an unsafe IP address template in your browser (e.g., `http://192.168.1.1` or long hyphenated login strings) to watch the *Active Heuristic* indicator shift dynamically to **Danger/Suspicious**.
* **Tracker Bloat Test:** Open a news blog. Observe the tracker mapper capture third-party ad requests and increase the privacy risk score organically.

---

## Contributions & License
This project is open-source under the MIT License. Feel free to open issues or pull requests to improve the heuristic engine algorithm!
