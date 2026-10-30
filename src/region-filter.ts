/**
 * Ingestion Region Filtering & Observer Temporary Blocklist
 *
 * Parses ALLOWED_REGIONS into a sanitized, case-insensitive set of approved IATA codes,
 * evaluates incoming region codes, and enforces a 1-minute temporary reconnection
 * blocklist for Observers publishing unapproved IATA codes.
 */

export interface ObserverBlockRecord {
  publicKey: string;
  unapprovedIata: string;
  blockedAt: number;
  blockedUntil: number;
  rejectedReconnects: number;
}

export interface ObserverRegionBlocklistStats {
  blockedObserverCount: number;
  totalBlocksIssued: number;
  totalBlockedReconnects: number;
  blockDurationSeconds: number;
  blockedObservers: {
    publicKeyPrefix: string;
    publicKey: string;
    unapprovedIata: string;
    blockedAt: number;
    blockedUntil: number;
    remainingSeconds: number;
    rejectedReconnects: number;
  }[];
}

/**
 * Parse ALLOWED_REGIONS environment variable into a sanitized Set of approved region codes.
 * Returns null if ALLOWED_REGIONS is undefined or blank (bypass mode).
 * Throws if a non-blank value contains no valid codes, so a typo (e.g. "DFW;ORD") fails closed
 * instead of silently disabling the filter.
 */
export function parseAllowedRegions(
  raw?: string,
  isValidIata?: (code: string) => boolean
): Set<string> | null {
  if (raw === undefined || raw === null) {
    return null;
  }

  const trimmedRaw = raw.trim();
  if (trimmedRaw.length === 0) {
    return null;
  }

  const approved = new Set<string>();
  const tokens = trimmedRaw.split(',').map((t) => t.trim()).filter((t) => t.length > 0);

  for (const token of tokens) {
    if (token.toLowerCase() === 'test') {
      approved.add('test');
      continue;
    }

    if (/^[A-Z]{3}$/i.test(token)) {
      const upper = token.toUpperCase();
      if (upper === 'XXX') {
        console.warn('[CONFIG] Warning: Ignoring placeholder code "XXX" in ALLOWED_REGIONS');
        continue;
      }
      if (isValidIata && !isValidIata(upper)) {
        console.warn(
          `[CONFIG] Warning: ALLOWED_REGIONS code "${upper}" is not recognized by airport-utils, but will still be permitted`
        );
      }
      approved.add(upper);
    } else {
      console.warn(
        `[CONFIG] Warning: Ignoring invalid region code "${token}" in ALLOWED_REGIONS (expected 3-letter IATA code or "test")`
      );
    }
  }

  if (approved.size === 0) {
    throw new Error(
      `ALLOWED_REGIONS is set but contains no valid region codes ("${trimmedRaw}"); expected comma-separated 3-letter IATA codes or "test"`
    );
  }

  return approved;
}

/**
 * Check whether an incoming region code is permitted under the active ALLOWED_REGIONS set.
 * When allowedRegions is null or undefined, all regions are permitted unconditionally.
 */
export function isRegionAllowed(
  locationCode: string,
  allowedRegions: Set<string> | null | undefined
): boolean {
  if (!allowedRegions) {
    return true;
  }

  const trimmed = locationCode.trim();
  if (!trimmed) {
    return false;
  }

  const normalized = trimmed.toLowerCase() === 'test' ? 'test' : trimmed.toUpperCase();
  return allowedRegions.has(normalized);
}

/**
 * Temporary in-memory blocklist for Observers that publish an unapproved IATA code.
 * Rejects reconnection attempts by Observer Public Key until the timer expires (default: 1 minute).
 */
export class ObserverRegionBlocklist {
  private readonly blockedByPubKey = new Map<string, ObserverBlockRecord>();
  private readonly blockDurationMs: number;
  private readonly maxEntries: number;
  private cleanupInterval?: NodeJS.Timeout;
  private totalBlocksIssued = 0;
  private totalBlockedReconnects = 0;

  constructor(
    blockDurationMs: number = 60_000,   // 1 minute default
    maxEntries: number = 10_000,        // Bound memory usage
    cleanupIntervalMs: number = 60_000  // Prune expired records every 1 minute
  ) {
    this.blockDurationMs = blockDurationMs;
    this.maxEntries = maxEntries;

    if (cleanupIntervalMs > 0) {
      this.cleanupInterval = setInterval(() => {
        this.cleanupExpired();
      }, cleanupIntervalMs);
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref();
      }
    }
  }

  /**
   * Prune expired block records from memory.
   */
  public cleanupExpired(now: number = Date.now()): void {
    for (const [key, rec] of this.blockedByPubKey.entries()) {
      if (now >= rec.blockedUntil) {
        this.blockedByPubKey.delete(key);
      }
    }
  }

  /**
   * Place an Observer's public key on the temporary blocklist.
   */
  public block(publicKey: string, unapprovedIata: string, now: number = Date.now()): void {
    const normalizedKey = publicKey.trim().toUpperCase();
    if (!normalizedKey) return;

    const normalizedIata =
      unapprovedIata.trim().toLowerCase() === 'test'
        ? 'test'
        : unapprovedIata.trim().toUpperCase();

    if (!this.blockedByPubKey.has(normalizedKey) && this.blockedByPubKey.size >= this.maxEntries) {
      this.cleanupExpired(now);
      if (this.blockedByPubKey.size >= this.maxEntries) {
        // Evict oldest entry if still at max capacity
        const oldestKey = this.blockedByPubKey.keys().next().value;
        if (oldestKey) {
          this.blockedByPubKey.delete(oldestKey);
        }
      }
    }

    // Refresh insertion order
    this.blockedByPubKey.delete(normalizedKey);
    this.blockedByPubKey.set(normalizedKey, {
      publicKey: normalizedKey,
      unapprovedIata: normalizedIata,
      blockedAt: now,
      blockedUntil: now + this.blockDurationMs,
      rejectedReconnects: 0,
    });
    this.totalBlocksIssued++;
  }

  /**
   * Check whether an Observer public key is currently blocked, and return remaining cooldown details.
   * Increments rejectedReconnects when an active block is hit.
   */
  public checkBlock(
    publicKey: string,
    recordReconnectAttempt: boolean = true,
    now: number = Date.now()
  ): {
    blocked: boolean;
    remainingSeconds: number;
    unapprovedIata?: string;
    blockedUntil?: number;
  } {
    const normalizedKey = publicKey.trim().toUpperCase();
    const record = this.blockedByPubKey.get(normalizedKey);
    if (!record) {
      return { blocked: false, remainingSeconds: 0 };
    }

    if (now >= record.blockedUntil) {
      this.blockedByPubKey.delete(normalizedKey);
      return { blocked: false, remainingSeconds: 0 };
    }

    if (recordReconnectAttempt) {
      record.rejectedReconnects++;
      this.totalBlockedReconnects++;
    }

    return {
      blocked: true,
      remainingSeconds: Math.max(1, Math.ceil((record.blockedUntil - now) / 1000)),
      unapprovedIata: record.unapprovedIata,
      blockedUntil: record.blockedUntil,
    };
  }

  /**
   * Convenience boolean check for whether an Observer public key is currently blocked.
   */
  public isBlocked(publicKey: string, recordReconnectAttempt: boolean = true): boolean {
    return this.checkBlock(publicKey, recordReconnectAttempt).blocked;
  }

  /**
   * Return a bounded snapshot of blocklist metrics for $SYS telemetry.
   */
  public getStats(maxBlockedList: number = 50): ObserverRegionBlocklistStats {
    const now = Date.now();
    const blockedObservers: ObserverRegionBlocklistStats['blockedObservers'] = [];
    let blockedObserverCount = 0;

    for (const [key, rec] of this.blockedByPubKey.entries()) {
      if (now >= rec.blockedUntil) {
        this.blockedByPubKey.delete(key);
        continue;
      }
      blockedObserverCount++;
      if (blockedObservers.length < maxBlockedList) {
        blockedObservers.push({
          publicKeyPrefix: rec.publicKey.substring(0, 8),
          publicKey: rec.publicKey,
          unapprovedIata: rec.unapprovedIata,
          blockedAt: rec.blockedAt,
          blockedUntil: rec.blockedUntil,
          remainingSeconds: Math.max(1, Math.ceil((rec.blockedUntil - now) / 1000)),
          rejectedReconnects: rec.rejectedReconnects,
        });
      }
    }

    return {
      blockedObserverCount,
      totalBlocksIssued: this.totalBlocksIssued,
      totalBlockedReconnects: this.totalBlockedReconnects,
      blockDurationSeconds: Math.round(this.blockDurationMs / 1000),
      blockedObservers,
    };
  }

  /**
   * Total number of tracked records in the map (for testing and metrics).
   */
  public getRecordCount(): number {
    return this.blockedByPubKey.size;
  }

  /**
   * Clean up background timer on broker shutdown.
   */
  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
    this.blockedByPubKey.clear();
    this.totalBlocksIssued = 0;
    this.totalBlockedReconnects = 0;
  }
}
