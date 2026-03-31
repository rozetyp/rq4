# RQ4: Request Context Fingerprinting

**Version 1.0 — March 2026**

## Abstract

RQ4 is a method for fingerprinting HTTP clients by analyzing whether request header combinations are consistent with real browser behavior. Unlike TLS fingerprinting (JA3/JA4) which examines *how* a connection is established, or HTTP header fingerprinting (JA4H) which examines *what* headers are present, RQ4 examines whether the headers are *logically valid* given the request context.

Modern browser impersonation tools can perfectly replicate browser TLS handshakes and header sets. However, these tools set headers statically at session creation and reuse them across all request types. Real browsers are state machines that dynamically generate headers based on request context — navigation vs. fetch, GET vs. POST, same-origin vs. cross-origin, user-activated vs. programmatic. RQ4 exploits this architectural gap.

RQ4 defines four analysis dimensions and produces a compact fingerprint indicating which dimensions contain impossible states. A request that fails any RQ4 dimension was not produced by a standard browser — regardless of how convincing its TLS fingerprint or User-Agent string appears.

---

## 1. Background

### 1.1 The Detection Gap

Bot detection has evolved through several layers:

| Layer | Standard | Detects | Evaded by |
|---|---|---|---|
| IP reputation | IP databases | Datacenter IPs, known VPNs | Residential proxies |
| TLS fingerprinting | JA3 (2017), JA4 (2023) | Default HTTP libraries | TLS impersonation libraries |
| HTTP header fingerprinting | JA4H (2023) | Missing/reordered headers | Header replication from browser profiles |
| JavaScript challenges | Client-side JS sensors | Headless browsers without full DOM | Patched browsers, browser farms |
| **Request context analysis** | **RQ4 (2026)** | **Static header configurations** | **Requires reimplementing browser request context logic** |

RQ4 fills the gap between TLS/header fingerprinting (which bot tools have learned to spoof) and JavaScript challenges (which cannot run on API endpoints, webhooks, or non-browser HTTP surfaces).

### 1.2 Why Static Headers Fail

When a real browser makes requests, it generates different header sets depending on context:

**User clicks a link (top-level navigation, GET):**
```
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none | same-origin | cross-site
Sec-Fetch-Dest: document
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,...
```

**JavaScript calls fetch() (programmatic, POST with JSON body):**
```
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Sec-Fetch-Dest: empty
[no Sec-Fetch-User]
[no Upgrade-Insecure-Requests]
Accept: */*
```

Bot tooling sets headers once at session creation — typically copying the navigation set — and reuses them for every request type. This produces logically impossible combinations: navigation headers on API calls, document destinations on CORS requests, user-activation signals on programmatic fetches.

RQ4 formalizes the rules that distinguish valid from impossible combinations.

---

## 2. Specification

### 2.1 Dimensions

RQ4 analyzes four dimensions of request context validity. Each dimension evaluates one or more header fields against the request method, body presence, and other headers.

| Dimension | Code | Headers analyzed | Tests |
|---|---|---|---|
| Mode | M | `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, HTTP method | Is the Mode × Dest × Method combination possible? |
| Upgrade | U | `Upgrade-Insecure-Requests`, `Sec-Fetch-User`, `Sec-Fetch-Mode` | Are navigation-only signals present on non-navigation requests? |
| Identity | I | `Sec-CH-UA-*`, `User-Agent`, `Accept-Language`, `Accept-Encoding` | Are identity signals internally consistent? |
| Transfer | T | `Content-Type`, `Content-Length`, `Accept`, `Sec-CH-UA`, HTTP method | Are transfer-related headers consistent with request context? |

The RQ4 fingerprint is a 4-character string where each character represents the result for that dimension: `v` (valid), `x` (impossible), or `-` (insufficient data to evaluate).

**Example fingerprints:**
- `vvvv` — All four dimensions valid. Consistent with a real browser.
- `xvvv` — Mode dimension impossible. Likely a bot with static Sec-Fetch headers.
- `xxvx` — Mode and Upgrade impossible, Transfer impossible. High-confidence bot.
- `--v-` — Only Identity dimension had enough headers to evaluate; it passed.

### 2.2 Dimension M — Mode Context

Sec-Fetch-Mode and Sec-Fetch-Dest are set by the browser engine according to the Fetch specification (https://fetch.spec.whatwg.org/). The valid combinations are constrained.

#### 2.2.1 Mode × Dest Validity Matrix

| Sec-Fetch-Mode | Valid Sec-Fetch-Dest values |
|---|---|
| `navigate` | `document`, `iframe`, `frame`, `embed`, `object` |
| `same-origin` | `empty`, `font`, `image`, `script`, `style`, `video`, `audio`, `track`, `worker`, `manifest` |
| `cors` | `empty`, `font`, `image`, `script`, `style`, `video`, `audio`, `track` |
| `no-cors` | `empty`, `image`, `script`, `style`, `video`, `audio`, `track`, `report` |
| `websocket` | `empty` (only) |

**Impossible states (RQ4-M fires):**

| Condition | Why impossible |
|---|---|
| `mode:navigate` + `dest:empty` | Navigation always targets a document or frame |
| `mode:cors` + `dest:document` | CORS requests never target top-level documents |
| `mode:no-cors` + `dest:document` | Same as above |
| `mode:websocket` + `dest:` anything other than `empty` | WebSocket upgrades have no resource destination |

#### 2.2.2 Navigate + POST (Refinement)

**Important:** Real browsers DO produce `Sec-Fetch-Mode: navigate` on POST requests — specifically during HTML form submissions (`<form method="POST" action="...">`). Therefore `navigate + POST` alone is NOT an impossible state.

However, the following IS impossible:

| Condition | Why impossible |
|---|---|
| `mode:navigate` + `dest:empty` + POST | A form submission navigates to a document, never to `dest:empty` |
| `mode:navigate` + POST + `Accept: */*` | Form submissions send HTML-capable Accept headers |

When Sec-Fetch headers are absent entirely, Dimension M returns `-` (indeterminate). Missing headers are not inherently suspicious — they may indicate an older browser, a non-browser client that doesn't claim to be a browser, or a privacy extension that strips headers.

### 2.3 Dimension U — Upgrade Context

Two headers are sent exclusively with user-activated top-level navigations:

- **`Upgrade-Insecure-Requests: 1`** — Defined in the W3C Upgrade Insecure Requests spec. Sent only on navigation requests to indicate the client prefers HTTPS.
- **`Sec-Fetch-User: ?1`** — Sent only when a navigation was triggered by user activation (click, form submission, Enter key). Never sent on programmatic navigations (e.g., `window.location` assignment without user gesture).

**Impossible states (RQ4-U fires):**

| Condition | Why impossible |
|---|---|
| `Upgrade-Insecure-Requests: 1` + `Sec-Fetch-Mode: cors` | UIR is navigation-only; CORS is never a navigation |
| `Upgrade-Insecure-Requests: 1` + `Sec-Fetch-Mode: no-cors` | Same reason |
| `Upgrade-Insecure-Requests: 1` + `Sec-Fetch-Mode: same-origin` | Same reason |
| `Sec-Fetch-User: ?1` + `Sec-Fetch-Mode: cors` | User activation only applies to navigations |
| `Sec-Fetch-User: ?1` + `Sec-Fetch-Mode: same-origin` | Same reason |
| `Sec-Fetch-User: ?1` + `Sec-Fetch-Mode: no-cors` | Same reason |

**Note on `Sec-Fetch-Mode: navigate` + absence of `Sec-Fetch-User`:** This is valid. It indicates a programmatic navigation (redirect, `window.location`, meta refresh) without user activation. The presence of `Sec-Fetch-User: ?1` on a non-navigate mode is impossible; the absence of `Sec-Fetch-User` on navigate mode is normal.

### 2.4 Dimension I — Identity Coherence

Browsers send identity-related headers that must be internally consistent. RQ4-I checks cross-header coherence, not individual header values.

**Impossible states (RQ4-I fires):**

| Condition | Why impossible |
|---|---|
| `Sec-CH-UA` present + Firefox `User-Agent` | Firefox does not implement Client Hints (as of March 2026) |
| `Sec-CH-UA` present + Safari `User-Agent` | Safari does not implement Client Hints (as of March 2026) |
| `Sec-CH-UA-Platform: "Windows"` + macOS `User-Agent` | Platform mismatch between hints and UA |
| `Sec-CH-UA-Mobile: ?1` + desktop `User-Agent` | Mobile hint contradicts desktop UA |
| All Chromium Sec-CH-UA-* headers present + no `Accept-Language` | Chromium always sends Accept-Language; its absence with full Client Hints suggests header list was constructed, not generated |

**Not flagged by RQ4-I:**

- Missing `Sec-CH-UA` entirely (older Chrome, Brave shields, privacy extensions)
- `User-Agent` string not recognized (new or rare browser)
- Missing `Accept-Language` without Client Hints present (could be any non-Chromium client)

RQ4-I requires positive signals of inconsistency, not absence of signals. This avoids false positives on privacy-focused browsers that strip headers.

**Note:** The Client Hints checks in Dimension I require maintenance as browsers evolve. Implementations should use a version-aware lookup rather than hardcoded assumptions about which browsers support Client Hints.

### 2.5 Dimension T — Transfer Context

Request body handling and content negotiation follow predictable browser patterns that bot tooling frequently violates.

**Impossible states (RQ4-T fires):**

| Condition | Why impossible |
|---|---|
| `Content-Type: application/x-www-form-urlencoded` + `Content-Length: 0` + `Sec-Fetch-Site: none` | Browsers do not send Content-Type on empty-body requests initiated as top-level navigations. |
| `Accept: text/html,...` + request body present + `Sec-CH-UA` present + `Sec-Fetch-Mode: cors` | Chromium's `fetch()` sends `Accept: */*`, not HTML accept. HTML accept with a body on a CORS request indicates a navigation header set reused on a fetch-type request. |
| `Accept: text/html,...` + `Sec-Fetch-Mode: cors` | CORS fetch in Chromium always sends `Accept: */*` unless explicitly overridden by application code. |

**Not flagged by RQ4-T:**

- `Accept: */*` on any request (valid default for programmatic requests)
- Custom `Content-Type` headers on POST (applications set these legitimately)
- Missing `Accept` header (some HTTP libraries omit it)

---

## 3. Implementation

### 3.1 Algorithm

For each incoming HTTP request:

```
function computeRQ4(request):
    M = evaluateMode(request)
    U = evaluateUpgrade(request)
    I = evaluateIdentity(request)
    T = evaluateTransfer(request)
    return M + U + I + T    // e.g., "xvvx"
```

Each dimension function returns one of:
- `v` — All evaluated rules passed. Consistent with browser behavior.
- `x` — One or more impossible states detected. Not consistent with any browser.
- `-` — Insufficient headers present to make a determination.

### 3.2 Scoring

The RQ4 fingerprint can be used directly as a categorical signal or converted to a numeric score:

| Result | Meaning | Suggested weight |
|---|---|---|
| `x` on any dimension | Impossible browser state detected | High confidence bot signal |
| Multiple `x` results | Multiple impossible states | Very high confidence |
| All `v` | Consistent with browser | Does not prove human (bots can generate valid contexts) |
| All `-` | No Sec-Fetch headers present | Indeterminate — evaluate with other signals |

**Critical: RQ4 is a one-way signal.** An `x` result is a strong positive indicator of non-browser origin. A `v` result does NOT prove browser origin — a sufficiently sophisticated client can produce valid header contexts. RQ4 is designed to be combined with TLS fingerprinting (JA3/JA4), IP intelligence, behavioral analysis, and other detection layers.

### 3.3 Platform Support

RQ4 requires access to HTTP request headers. It can be implemented on any reverse proxy, web server, or middleware that exposes headers before the response is generated:

- **Cloudflare Workers** — via `request.headers`
- **Nginx** — via `ngx_http_lua_module` or njs
- **Caddy** — via middleware plugins
- **Express/Node.js** — via middleware
- **Vercel Edge Middleware** — via `request.headers`
- **AWS CloudFront** — via Lambda@Edge or CloudFront Functions

RQ4's header context analysis works independently of TLS signals, though combining both produces stronger detection.

---

## 4. Detection Results

### 4.1 False Positive Testing

Tested against 9 real browsers via a cloud testing platform and 4 real physical devices:

| Browser | OS | RQ4 Result |
|---|---|---|
| Chrome 146 | Windows 11 | `vvvv` |
| Chrome 146 | Windows 10 | `vvvv` |
| Chrome 146 | macOS | `vvvv` |
| Firefox 137 | Windows 11 | `vv-v` (no Client Hints — I is indeterminate) |
| Firefox 137 | macOS | `vv-v` |
| Safari 26 | macOS | `vv-v` |
| Edge 146 | Windows 11 | `vvvv` |
| Chrome 146 | Android (Pixel 8) | `vvvv` |
| Chrome 146 | Android (Samsung S23) | `vvvv` |
| Safari | iOS 18 (iPhone, real device) | `vv-v` |

**Zero false positives across 4 browser engines, 3 operating systems, desktop and mobile.**

### 4.2 Bot Detection

| Client | RQ4 Result | Dimensions fired |
|---|---|---|
| curl (default) | `----` | No Sec-Fetch headers at all |
| Browser impersonation tool (default static headers, POST) | `xvvx` | M: impossible Mode+Dest; T: impossible Transfer context |
| Browser impersonation tool (mixed navigation/cors headers) | `xxvx` | M + U + T fired |
| Browser impersonation tool (patched per-request headers) | `vvvv` | All valid (evasion successful) |
| Python requests | `----` | No Sec-Fetch headers at all |
| Go net/http | `----` | No Sec-Fetch headers at all |

---

## 5. Limitations

### 5.1 Evasion

RQ4 can be evaded by clients that generate context-appropriate headers per-request, which requires reimplementing browser request dispatch logic — mapping each request type to the correct combination of Sec-Fetch-Mode, Sec-Fetch-Dest, Sec-Fetch-User, Upgrade-Insecure-Requests, Accept, and Content-Type. This is achievable but requires significantly more effort than static header copying, and most automation tooling does not implement it by default.

### 5.2 Indeterminate Results

Clients that do not send Sec-Fetch headers produce `----` (all indeterminate). RQ4 cannot distinguish these clients from each other — it can only identify clients that *claim* to be browsers but produce impossible browser states.

This is by design. RQ4 detects *impersonation failures*, not all automated traffic. It is most effective against the specific threat of browser-impersonating bots that set Sec-Fetch and Client Hints headers to mimic modern browsers.

### 5.3 Browser Evolution

Browser header behavior changes across versions. New headers may be added, existing header semantics may change, and new Sec-Fetch-Mode or Sec-Fetch-Dest values may be introduced. The RQ4 validity matrices must be updated as browsers evolve.

The reference implementation should treat unknown header values as valid (not impossible) to avoid false positives on new browser versions before the spec is updated.

### 5.4 Privacy Extensions

Browser extensions that modify or strip Sec-Fetch headers may reduce RQ4's ability to evaluate requests. The spec handles this through the indeterminate (`-`) result — missing headers produce indeterminate, not impossible, results.

---

## 6. Relationship to Other Standards

| Standard | Layer | Analyzes | Complementary to RQ4? |
|---|---|---|---|
| JA3 (2017) | TLS | Cipher suites, extensions | Yes — different layer |
| JA4 (2023) | TLS | Sorted ciphers/extensions, ALPN | Yes — different layer |
| JA4H (2023) | HTTP | Header names, order, values | Partially — JA4H checks presence, RQ4 checks logical consistency |
| JA4T (2023) | TCP | Window size, TTL, options | Yes — different layer |
| p0f (2003) | TCP/HTTP | OS fingerprinting | Minimal overlap |
| Akamai HTTP/2 FP (2017) | HTTP/2 | SETTINGS, WINDOW_UPDATE, PRIORITY | Yes — different layer |

RQ4 is designed to be used alongside these standards, not to replace them. The strongest detection combines TLS fingerprinting (catches unsophisticated bots), RQ4 analysis (catches browser-impersonating bots with static headers), and behavioral analysis (catches fully patched bots through usage patterns).

---

## 7. Reference Implementation

- **Live demo:** https://rq4.dev
- **GitHub:** [TBD]

The reference implementation is approximately 300 lines of TypeScript for core RQ4 analysis.

---

## 8. Future Work

### 8.1 RQ4+ Extensions

Following the JA4+ model, RQ4 can be extended to additional dimensions:

- **RQ4-C (Cookie context):** SameSite cookie behavior vs. Sec-Fetch-Site consistency
- **RQ4-R (Referer context):** Referrer-Policy compliance vs. actual Referer header presence
- **RQ4-O (Origin context):** Origin header presence/absence vs. request mode and method
- **RQ4-P (Preflight context):** CORS preflight consistency for cross-origin requests
- **RQ4-H2 (HTTP/2 context):** Pseudo-header ordering and SETTINGS frame consistency with claimed browser

### 8.2 Empirical Validity Matrix

The validity matrices in Section 2 are derived from the Fetch specification and verified against real browser behavior. A large-scale empirical study across diverse browser populations would strengthen the spec by identifying edge cases, extension-modified behavior, and WebView variations.

### 8.3 Standard Identifier Format

A future version may define a compact hash format (similar to JA3/JA4 hashes) encoding the full set of header context signals into a single searchable string, enabling RQ4 fingerprints to be logged, shared, and correlated across deployments.

---

## Authors

AZ

## License

The RQ4 specification is released under Creative Commons Attribution 4.0 International (CC BY 4.0). Anyone may implement, use, modify, and distribute implementations of this specification for any purpose, including commercial use, with attribution.

## Citation

```
RQ4: Request Context Fingerprinting. Version 1.0, March 2026.
AZ.
https://rq4.dev
```
