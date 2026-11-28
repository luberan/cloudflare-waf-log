// Security headers for static asset responses. Kept free of Workers-specific types so the browser
// smoke tests can serve the dashboard under exactly the same policy as production.
//
// The dashboard self-hosts all of its scripts (Chart.js lives in /vendor, the app logic in /app.js),
// so the CSP can lock scripts to same-origin. Cloudflare Bot JavaScript Detections recognizes a nonce
// in the response CSP and adds it to the inline snippet it injects later at the edge. Inline styles /
// style attributes are still used, hence 'unsafe-inline' for style only.
export const STATIC_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  // Browsers ignore HSTS on plain-HTTP responses, so this does not affect local `wrangler dev`.
  "strict-transport-security": "max-age=31536000",
};

export function contentSecurityPolicy(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const nonce = btoa(binary);
  return (
    "default-src 'self'; " +
    `script-src 'self' 'nonce-${nonce}'; ` +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'none'; " +
    "object-src 'none'; " +
    "form-action 'self'"
  );
}

/** All headers a static asset response gets, including a fresh per-response CSP nonce. */
export function staticSecurityHeaders(): Record<string, string> {
  return { ...STATIC_SECURITY_HEADERS, "content-security-policy": contentSecurityPolicy() };
}
