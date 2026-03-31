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

  return { passed, failed, results };
}
