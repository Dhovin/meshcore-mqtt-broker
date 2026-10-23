import { timingSafeEqual } from 'crypto';

/**
 * Timing-safe string comparison to prevent side-channel timing attacks
 * Returns true if both strings match, false otherwise
 */
export function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    // Perform dummy comparison to keep execution timing roughly constant
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
