/**
 * RQ4: Request Context Fingerprinting
 * Reference Implementation v1.0
 * 
 * Analyzes HTTP request headers for logically impossible browser states.
 * Returns a 4-character fingerprint: M(ode) U(pgrade) I(dentity) T(ransfer)
 * Each character: 'v' (valid), 'x' (impossible), '-' (indeterminate)
 * 
 * License: MIT
 */

export interface RQ4Input {
  method: string;                    // GET, POST, PUT, etc.
  headers: Record<string, string>;   // Lowercase header names
  hasBody: boolean;                  // Whether request has a body (Content-Length > 0 or Transfer-Encoding present)
}

export interface RQ4Result {
  fingerprint: string;               // e.g. "xvvx"
  dimensions: {
    mode: DimensionResult;
    upgrade: DimensionResult;
    identity: DimensionResult;
    transfer: DimensionResult;
  };
}

export interface DimensionResult {
  code: 'v' | 'x' | '-';
  signals: string[];                 // Which specific rules fired (for logging)
}

// ─── Valid Mode × Dest combinations (from Fetch spec) ───────────────────────
// Key: Sec-Fetch-Mode value
// Value: Set of valid Sec-Fetch-Dest values for that mode

const VALID_MODE_DEST: Record<string, Set<string>> = {
  'navigate': new Set(['document', 'iframe', 'frame', 'embed', 'object']),
  'same-origin': new Set(['empty', 'font', 'image', 'script', 'style', 'video', 'audio', 'track', 'worker', 'sharedworker', 'manifest', 'report', 'xslt', 'json']),
  'cors': new Set(['empty', 'font', 'image', 'script', 'style', 'video', 'audio', 'track', 'sharedworker', 'manifest', 'report', 'xslt', 'json']),
  'no-cors': new Set(['empty', 'image', 'script', 'style', 'video', 'audio', 'track', 'report', 'object', 'embed']),
  'websocket': new Set(['empty', 'websocket']),
};

// ─── Dimension M: Mode Context ──────────────────────────────────────────────

function evaluateMode(input: RQ4Input): DimensionResult {
  const mode = input.headers['sec-fetch-mode'];
  const dest = input.headers['sec-fetch-dest'];
  const signals: string[] = [];

  // Need at least mode to evaluate
  if (!mode) {
    return { code: '-', signals: [] };
  }

  // Check Mode × Dest validity if dest is present
  if (dest) {
    const validDests = VALID_MODE_DEST[mode];
    if (validDests && !validDests.has(dest)) {
      signals.push(`mode_dest_invalid: ${mode}+${dest}`);
    }

    // Special case: navigate + dest:empty is always impossible
    // (navigations always target a document, frame, or embeddable resource)
    if (mode === 'navigate' && dest === 'empty') {
      signals.push('navigate_dest_empty');
    }
  }

  // navigate + POST + dest:empty (if dest present)
  // Note: navigate + POST alone is valid (form submissions)
  // But navigate + POST + dest:empty is impossible because
  // form submissions navigate to a document
  if (mode === 'navigate' && input.method === 'POST' && dest === 'empty') {
    // Already caught by navigate_dest_empty above, but add specific signal
    if (!signals.includes('navigate_dest_empty')) {
      signals.push('navigate_post_dest_empty');
    }
  }

  return {
    code: signals.length > 0 ? 'x' : 'v',
    signals
  };
}

// ─── Dimension U: Upgrade Context ───────────────────────────────────────────

function evaluateUpgrade(input: RQ4Input): DimensionResult {
  const mode = input.headers['sec-fetch-mode'];
  const uir = input.headers['upgrade-insecure-requests'];
  const fetchUser = input.headers['sec-fetch-user'];
  const signals: string[] = [];

  // Need mode to evaluate
  if (!mode) {
    return { code: '-', signals: [] };
  }

  const isNavigation = mode === 'navigate';

  // If neither UIR nor Sec-Fetch-User present:
  // - On non-navigate: correct behavior (these are navigation-only headers)
  // - On navigate: also valid (programmatic navigation, no user activation)
  // Either way, no impossible state detected → return valid
  if (!uir && !fetchUser) {
    return { code: 'v', signals: [] };
  }

  // UIR should only be present on navigation requests
  if (uir === '1' && !isNavigation) {
    signals.push(`uir_on_${mode}`);
  }

  // Sec-Fetch-User: ?1 should only be present on navigation requests
  // (specifically user-activated navigations)
  if (fetchUser === '?1' && !isNavigation) {
    signals.push(`fetch_user_on_${mode}`);
  }

  return {
    code: signals.length > 0 ? 'x' : 'v',
    signals
  };
}

// ─── Dimension I: Identity Coherence ────────────────────────────────────────

function evaluateIdentity(input: RQ4Input): DimensionResult {
  const ua = input.headers['user-agent'] || '';
  const secChUa = input.headers['sec-ch-ua'];
  const secChUaPlatform = input.headers['sec-ch-ua-platform'];
  const secChUaMobile = input.headers['sec-ch-ua-mobile'];
  const acceptLang = input.headers['accept-language'];
  const signals: string[] = [];

  // Need Client Hints to cross-reference. Without them, UA alone
  // doesn't give us enough to detect inconsistency.
  if (!secChUa && !secChUaPlatform && !secChUaMobile) {
    return { code: '-', signals: [] };
  }

  // If Client Hints present, check UA consistency
  if (secChUa) {
    const uaLower = ua.toLowerCase();

    // Firefox does not implement Client Hints
    if (uaLower.includes('firefox/') && !uaLower.includes('chrome/')) {
      signals.push('client_hints_with_firefox');
    }

    // Safari does not implement Client Hints
    if (uaLower.includes('safari/') && !uaLower.includes('chrome/') && !uaLower.includes('chromium/')) {
      signals.push('client_hints_with_safari');
    }
  }

  // Platform mismatch: Sec-CH-UA-Platform vs User-Agent
  if (secChUaPlatform && ua) {
    const platform = secChUaPlatform.replace(/"/g, '').toLowerCase();
    const uaLower = ua.toLowerCase();

    if (platform === 'windows' && uaLower.includes('macintosh')) {
      signals.push('platform_windows_ua_mac');
    }
    if (platform === 'macos' && uaLower.includes('windows nt')) {
      signals.push('platform_mac_ua_windows');
    }
    if (platform === 'linux' && (uaLower.includes('windows nt') || uaLower.includes('macintosh'))) {
      signals.push('platform_linux_ua_desktop_other');
    }
  }

  // Mobile mismatch: Sec-CH-UA-Mobile vs User-Agent
  if (secChUaMobile && ua) {
    const isMobileHint = secChUaMobile === '?1';
    const uaLower = ua.toLowerCase();
    const isMobileUA = uaLower.includes('mobile') || uaLower.includes('android');
    const isDesktopUA = (uaLower.includes('windows nt') || uaLower.includes('macintosh')) && !isMobileUA;

    if (isMobileHint && isDesktopUA) {
      signals.push('mobile_hint_desktop_ua');
    }
    // Note: we don't flag mobile UA + desktop hint because
    // Chrome on Android tablets can send ?0
  }

  // Chromium with full Client Hints but no Accept-Language
  // Chromium always sends Accept-Language; its absence with Client Hints
  // suggests headers were assembled, not generated by a browser
  if (secChUa && secChUaPlatform && secChUaMobile && !acceptLang) {
    signals.push('full_client_hints_no_accept_language');
  }

  // We have at least some Client Hints data — return result
  return {
    code: signals.length > 0 ? 'x' : 'v',
    signals
  };
}

// ─── Dimension T: Transfer Context ──────────────────────────────────────────

function evaluateTransfer(input: RQ4Input): DimensionResult {
  const mode = input.headers['sec-fetch-mode'];
  const site = input.headers['sec-fetch-site'];
  const contentType = input.headers['content-type'];
  const contentLength = input.headers['content-length'];
  const accept = input.headers['accept'] || '';
  const secChUa = input.headers['sec-ch-ua'];
  const signals: string[] = [];

  // Need at least mode or content-type related headers to evaluate
  if (!mode && !contentType) {
    return { code: '-', signals: [] };
  }

  // Empty form-urlencoded on top-level navigation context
  // Browsers omit Content-Type when body is empty on top-level requests
  if (
    contentType &&
    contentType.includes('application/x-www-form-urlencoded') &&
    contentLength === '0' &&
    site === 'none'
  ) {
    signals.push('empty_form_urlencoded_site_none');
  }

  // HTML Accept header on CORS mode
  // Chromium's fetch() always sends Accept: */* unless overridden
  // Navigation-style Accept (text/html,...) on cors mode means
  // navigation headers were pasted onto a fetch-style request
  const hasHtmlAccept = accept.includes('text/html');
  if (hasHtmlAccept && mode === 'cors') {
    signals.push('html_accept_on_cors');
  }

  // HTML Accept + body + Client Hints + CORS mode
  // This is the strongest T signal: it's a Chromium-claiming client
  // sending navigation-style Accept on what should be a programmatic request
  if (hasHtmlAccept && input.hasBody && secChUa && mode === 'cors') {
    if (!signals.includes('html_accept_on_cors')) {
      signals.push('html_accept_body_cors_chromium');
    }
  }

  return {
    code: signals.length > 0 ? 'x' : 'v',
    signals
  };
}

// ─── Main RQ4 Function ──────────────────────────────────────────────────────

export function computeRQ4(input: RQ4Input): RQ4Result {
  // Normalize headers to lowercase keys
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(input.headers)) {
    normalized[key.toLowerCase()] = value;
  }

  const normalizedInput: RQ4Input = {
    method: input.method.toUpperCase(),
    headers: normalized,
    hasBody: input.hasBody,
  };

  const mode = evaluateMode(normalizedInput);
  const upgrade = evaluateUpgrade(normalizedInput);
  const identity = evaluateIdentity(normalizedInput);
  const transfer = evaluateTransfer(normalizedInput);

  return {
    fingerprint: mode.code + upgrade.code + identity.code + transfer.code,
    dimensions: { mode, upgrade, identity, transfer },
  };
}

// ─── Helper: Extract RQ4Input from standard Request object ──────────────────

export function rq4FromRequest(request: Request): RQ4Input {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const contentLength = headers['content-length'];
  const transferEncoding = headers['transfer-encoding'];
  const hasBody = (contentLength !== undefined && contentLength !== '0') ||
                  transferEncoding !== undefined ||
                  ['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase());

  return {
    method: request.method,
    headers,
    hasBody,
  };
}

// ─── Test Vectors ───────────────────────────────────────────────────────────
// These test vectors document expected behavior and can be used for
// implementation verification.

export const TEST_VECTORS: Array<{ name: string; input: RQ4Input; expected: string }> = [
  // Real browser: Chrome top-level navigation (GET)
  {
    name: 'chrome_navigation_get',
    input: {
      method: 'GET',
      headers: {
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="146", "Google Chrome";v="146"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-mobile': '?0',
      },
      hasBody: false,
    },
    expected: 'vvvv',
  },

  // Real browser: Chrome fetch() API call (POST JSON)
  {
    name: 'chrome_fetch_post',
    input: {
      method: 'POST',
      headers: {
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'sec-fetch-site': 'same-origin',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'content-length': '42',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="146", "Google Chrome";v="146"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-mobile': '?0',
      },
      hasBody: true,
    },
    expected: 'vvvv',
  },

  // Real browser: Chrome form submission (POST, navigate)
  {
    name: 'chrome_form_post',
    input: {
      method: 'POST',
      headers: {
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'content-length': '24',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="146", "Google Chrome";v="146"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-mobile': '?0',
      },
      hasBody: true,
    },
    expected: 'vvvv',
  },

  // Real browser: Firefox navigation (no Client Hints)
  {
    name: 'firefox_navigation',
    input: {
      method: 'GET',
      headers: {
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.5',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
      },
      hasBody: false,
    },
    expected: 'vv-v', // I is indeterminate: no Client Hints to cross-check
  },

  // Bot: impersonation tool chrome136 default headers on navigate POST
  {
    name: 'impersonation_tool_navigate_post',
    input: {
      method: 'POST',
      headers: {
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'empty',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'content-length': '0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-mobile': '?0',
      },
      hasBody: false,  // Content-Length: 0 means no actual body
    },
    expected: 'xvvx', // M: navigate+empty; T: empty form-urlencoded+site:none
  },

  // Bot: impersonation tool making a CORS-style POST but with navigation headers
  {
    name: 'impersonation_tool_cors_mixed_headers',
    input: {
      method: 'POST',
      headers: {
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'content-length': '42',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-mobile': '?0',
      },
      hasBody: true,
    },
    expected: 'vxvx', // M: cors+empty is valid; U: UIR+user on cors; I: valid Chrome hints+UA; T: html_accept_on_cors
  },

  // Bot: Python requests (no Sec-Fetch headers)
  {
    name: 'python_requests_default',
    input: {
      method: 'GET',
      headers: {
        'user-agent': 'python-requests/2.31.0',
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate',
      },
      hasBody: false,
    },
    expected: '----', // No Sec-Fetch headers, no Client Hints — all indeterminate
  },

  // Bot: Identity mismatch - Client Hints claiming Chrome but Firefox UA
  {
    name: 'identity_mismatch_hints_firefox',
    input: {
      method: 'GET',
      headers: {
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.5',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
        'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136"',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-mobile': '?0',
      },
      hasBody: false,
    },
    expected: 'vvxv', // I: Client Hints present with Firefox UA
  },

  // Bare curl (no impersonation)
  {
    name: 'cli_tool_bare',
    input: {
      method: 'GET',
      headers: {
        'user-agent': 'curl/8.7.1',
        'accept': '*/*',
      },
      hasBody: false,
    },
    expected: '----', // Nothing to evaluate
  },
];

// ─── Auxiliary signal: Encoding Coherence (NOT part of the M·U·I·T fingerprint) ─
//
// A supplementary check comparing the Chromium version a client CLAIMS against
// whether it advertises Zstandard ("zstd") in Accept-Encoding. Unlike the four
// fingerprint dimensions — which exploit per-request context that static header
// copying gets wrong — this compares two STATIC values (a version claim and a
// static header), so it is inherently copyable: a tool that keeps its
// Accept-Encoding consistent with the version it claims is not flagged. It is
// deliberately kept OUT of computeRQ4 so it never affects the core fingerprint or
// its false-positive guarantees. Use it, if at all, as a low-weight side signal.
//
// Ground truth (verified against real per-version browser behaviour):
//   * Chromium enabled zstd by DEFAULT in v123. v117 and earlier never sent it;
//     v118-122 shipped it behind an off-by-default flag (either state is legal).
//   * zstd is advertised only in secure (HTTPS) contexts.
//   * Non-Chromium browsers are out of scope: Firefox's threshold differs and
//     Safari does not advertise zstd even at v18. The check applies only to
//     clients that positively claim Chromium.
//
// Two coherence violations, with different confidence:
//   * inverse (zero false positives): claims Chromium <= 117 yet advertises zstd
//     — impossible; zstd did not exist in those versions.
//   * forward (very low false positives): claims Chromium >= 123 yet omits zstd
//     — caught: a browser UA on a plain HTTP client. Evaded: tooling that keeps
//     Accept-Encoding current. Real-browser residuals: enterprise policy
//     (ZstdContentEncodingEnabled=Disabled), some Chromium forks, and plain-HTTP
//     requests — callers that cannot assume HTTPS should treat forward as advisory.
//   * v118-122, consistent pairings, non-Chromium, or no Accept-Encoding →
//     no violation reported.
//
// CAVEAT: pass the ORIGINAL client Accept-Encoding. CDNs/proxies that normalize
// it (e.g. to "gzip, br") make this check meaningless — treat as indeterminate
// where the original value is unavailable.

export interface EncodingCoherenceResult {
  verdict: 'consistent' | 'inconsistent' | 'indeterminate';
  signal?: 'chromium_le117_unexpected_zstd' | 'chromium_ge123_missing_zstd';
  confidence?: 'high' | 'moderate';
  reason?: string;
}

function chromiumMajorVersion(headers: Record<string, string>): number | null {
  let major: number | null = null;

  // Prefer Sec-CH-UA brand versions (Chromium / Google Chrome / Microsoft Edge);
  // the "Not/A)Brand" GREASE entry is excluded by the allowlist.
  const secChUa = headers['sec-ch-ua'] || '';
  const brandRe = /"(?:chromium|google chrome|microsoft edge)";\s*v="(\d+)"/gi;
  let m: RegExpExecArray | null;
  while ((m = brandRe.exec(secChUa)) !== null) {
    const v = parseInt(m[1], 10);
    if (!Number.isNaN(v) && (major === null || v > major)) major = v;
  }
  if (major !== null) return major;

  // Fall back to the UA Chrome/Edg token (excludes Firefox, Safari, iOS CriOS/EdgiOS).
  const ua = (headers['user-agent'] || '').toLowerCase();
  const uaMatch = ua.match(/(?:chrome|edg)\/(\d+)/);
  if (uaMatch) {
    const v = parseInt(uaMatch[1], 10);
    if (!Number.isNaN(v)) return v;
  }
  return null;
}

export function encodingCoherence(input: RQ4Input): EncodingCoherenceResult {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) headers[k.toLowerCase()] = v;

  const acceptEncoding = headers['accept-encoding'];
  if (!acceptEncoding) {
    return { verdict: 'indeterminate', reason: 'no Accept-Encoding to evaluate' };
  }
  const chromiumMajor = chromiumMajorVersion(headers);
  if (chromiumMajor === null) {
    return { verdict: 'indeterminate', reason: 'client does not positively claim Chromium' };
  }
  const hasZstd = acceptEncoding.toLowerCase().includes('zstd');

  if (chromiumMajor <= 117 && hasZstd) {
    return {
      verdict: 'inconsistent',
      signal: 'chromium_le117_unexpected_zstd',
      confidence: 'high',
      reason: `Chromium ${chromiumMajor} predates zstd (default since v123) but Accept-Encoding advertises it`,
    };
  }
  if (chromiumMajor >= 123 && !hasZstd) {
    return {
      verdict: 'inconsistent',
      signal: 'chromium_ge123_missing_zstd',
      confidence: 'moderate',
      reason: `Chromium ${chromiumMajor} advertises zstd by default over HTTPS but Accept-Encoding omits it`,
    };
  }
  return { verdict: 'consistent' };
}

// Auxiliary test vectors for encodingCoherence (verdict-level; run by runTestVectors).
export const ENCODING_TEST_VECTORS: Array<{ name: string; input: RQ4Input; expected: EncodingCoherenceResult['verdict'] }> = [
  // Real Chrome 123+ advertising zstd → consistent
  { name: 'real_chrome_123_with_zstd', input: { method: 'GET', headers: { 'accept-encoding': 'gzip, deflate, br, zstd', 'sec-ch-ua': '"Chromium";v="123", "Google Chrome";v="123"', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36' }, hasBody: false }, expected: 'consistent' },
  // Real Chrome 120 with NO zstd (regression: real Chrome ≤120 never sent zstd) → consistent, must NOT be flagged
  { name: 'real_chrome_120_no_zstd', input: { method: 'GET', headers: { 'accept-encoding': 'gzip, deflate, br', 'sec-ch-ua': '"Chromium";v="120", "Google Chrome";v="120"', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }, hasBody: false }, expected: 'consistent' },
  // Flag band: Chrome 118 with zstd (flag on) → consistent, either state legal in 118-122
  { name: 'flag_band_chrome_118_with_zstd', input: { method: 'GET', headers: { 'accept-encoding': 'gzip, deflate, br, zstd', 'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118"', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36' }, hasBody: false }, expected: 'consistent' },
  // Forward: claims Chrome 136 (≥123) but no zstd (naive Chrome-UA-on-plain-lib) → inconsistent
  { name: 'forward_chrome_136_no_zstd', input: { method: 'GET', headers: { 'accept-encoding': 'gzip, deflate', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36' }, hasBody: false }, expected: 'inconsistent' },
  // Inverse: claims Chrome 95 (≤117) but advertises zstd → inconsistent (zero-FP direction)
  { name: 'inverse_chrome_95_with_zstd', input: { method: 'GET', headers: { 'accept-encoding': 'gzip, deflate, br, zstd', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36' }, hasBody: false }, expected: 'inconsistent' },
  // Non-Chromium (Firefox) → indeterminate (out of scope)
  { name: 'firefox_not_chromium', input: { method: 'GET', headers: { 'accept-encoding': 'gzip, deflate, br', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0' }, hasBody: false }, expected: 'indeterminate' },
  // No Accept-Encoding (e.g. normalized away) → indeterminate
  { name: 'no_accept_encoding', input: { method: 'GET', headers: { 'sec-ch-ua': '"Chromium";v="146", "Google Chrome";v="146"', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36' }, hasBody: false }, expected: 'indeterminate' },
];

// ─── Test Runner ────────────────────────────────────────────────────────────

export function runTestVectors(): { passed: number; failed: number; results: string[] } {
  let passed = 0;
  let failed = 0;
  const results: string[] = [];

  for (const vector of TEST_VECTORS) {
    const result = computeRQ4(vector.input);
    const ok = result.fingerprint === vector.expected;

    if (ok) {
      passed++;
      results.push(`✓ ${vector.name}: ${result.fingerprint}`);
    } else {
      failed++;
      results.push(`✗ ${vector.name}: expected ${vector.expected}, got ${result.fingerprint}`);

      // Show which dimensions differed
      for (const [dim, res] of Object.entries(result.dimensions)) {
        results.push(`  ${dim}: ${res.code} ${res.signals.length > 0 ? '(' + res.signals.join(', ') + ')' : ''}`);
      }
    }
  }

  // Auxiliary: Encoding Coherence vectors (verdict-level; not part of the fingerprint)
  for (const vector of ENCODING_TEST_VECTORS) {
    const result = encodingCoherence(vector.input);
    const ok = result.verdict === vector.expected;
    if (ok) {
      passed++;
      results.push(`✓ [aux] ${vector.name}: ${result.verdict}${result.signal ? ' (' + result.signal + ')' : ''}`);
    } else {
      failed++;
      results.push(`✗ [aux] ${vector.name}: expected ${vector.expected}, got ${result.verdict}`);
    }
  }

  return { passed, failed, results };
}
