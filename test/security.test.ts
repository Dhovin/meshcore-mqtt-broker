import { describe, it } from 'node:test';
import assert from 'node:assert';
import { timingSafeCompare } from '../src/crypto-utils';
import { RateLimiter } from '../src/rate-limiter';

describe('Security: Timing-Safe Password Comparison', () => {
  it('returns true for matching passwords', () => {
    assert.strictEqual(timingSafeCompare('secretpassword123', 'secretpassword123'), true);
    assert.strictEqual(timingSafeCompare('', ''), true);
  });

  it('returns false for mismatched passwords of equal length', () => {
    assert.strictEqual(timingSafeCompare('secretpassword123', 'secretpassword124'), false);
    assert.strictEqual(timingSafeCompare('aaaa', 'bbbb'), false);
  });

  it('returns false for mismatched passwords of different length', () => {
    assert.strictEqual(timingSafeCompare('short', 'muchlongerpassword'), false);
    assert.strictEqual(timingSafeCompare('password', ''), false);
    assert.strictEqual(timingSafeCompare('', 'password'), false);
  });
});

describe('Security: Bounded RateLimiter & Expiration Pruning', () => {
  it('caps map size at maxEntries to prevent memory exhaustion', () => {
    // Create rate limiter with small maxEntries=5
    const limiter = new RateLimiter(60000, 5, 300000, 5, 0);

    try {
      for (let i = 1; i <= 10; i++) {
        limiter.recordFailure(`192.168.1.${i}`);
      }

      // Must be capped at 5
      assert.strictEqual(limiter.getRecordCount(), 5);

      // Oldest IP (192.168.1.1) was evicted, so it is not in the map
      assert.strictEqual(limiter.isBlocked('192.168.1.1'), false);
    } finally {
      limiter.destroy();
    }
  });

  it('prunes expired entries during cleanup', () => {
    // Window of 50ms
    const limiter = new RateLimiter(50, 5, 50, 100, 0);

    try {
      limiter.recordFailure('10.0.0.1');
      limiter.recordFailure('10.0.0.2');
      assert.strictEqual(limiter.getRecordCount(), 2);

      // Wait 60ms for window to expire
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          limiter.cleanupExpired();
          assert.strictEqual(limiter.getRecordCount(), 0);
          resolve();
        }, 65);
      });
    } finally {
      limiter.destroy();
    }
  });

  it('blocks IP after reaching maxFailedConnections threshold', () => {
    const limiter = new RateLimiter(60000, 3, 300000, 10, 0);

    try {
      const testIP = '1.2.3.4';
      assert.strictEqual(limiter.isBlocked(testIP), false);

      limiter.recordFailure(testIP); // 1
      limiter.recordFailure(testIP); // 2
      assert.strictEqual(limiter.isBlocked(testIP), false);

      const blocked = limiter.recordFailure(testIP); // 3 (threshold reached)
      assert.strictEqual(blocked, true);
      assert.strictEqual(limiter.isBlocked(testIP), true);
    } finally {
      limiter.destroy();
    }
  });
});
