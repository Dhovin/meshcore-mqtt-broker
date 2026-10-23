import { IncomingMessage } from 'http';

/**
 * Extract the real client IP from an HTTP request, considering Cloudflare headers.
 * 
 * SECURITY NOTE:
 * This function trusts proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`).
 * When deploying behind Cloudflare (e.g. Cloudflare Tunnels) or a trusted reverse proxy,
 * this ensures the user's real remote IP is logged and rate-limited.
 * 
 * If exposing the broker directly to the public internet without a reverse proxy,
 * clients can spoof these headers in connection requests.
 */
export function getClientIP(req: IncomingMessage): string {
  // Cloudflare provides the real IP in CF-Connecting-IP header
  const cfConnectingIP = req.headers['cf-connecting-ip'];
  if (cfConnectingIP) {
    return Array.isArray(cfConnectingIP) ? cfConnectingIP[0] : cfConnectingIP;
  }

  // Fallback to X-Forwarded-For (take first IP in chain)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const forwardedIPs = Array.isArray(xForwardedFor) 
      ? xForwardedFor[0] 
      : xForwardedFor;
    return forwardedIPs.split(',')[0].trim();
  }

  // Fallback to X-Real-IP
  const xRealIP = req.headers['x-real-ip'];
  if (xRealIP) {
    return Array.isArray(xRealIP) ? xRealIP[0] : xRealIP;
  }

  // Last resort: socket remote address
  return req.socket.remoteAddress || 'unknown';
}
