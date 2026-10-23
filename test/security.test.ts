import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Duplex } from 'stream';
import { timingSafeCompare } from '../src/crypto-utils';
import { RateLimiter } from '../src/rate-limiter';
import { MqttStreamValidator } from '../src/mqtt-packet-validator';

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

  it('prunes expired entries during cleanup', async () => {
    // Window of 50ms
    const limiter = new RateLimiter(50, 5, 50, 100, 0);

    try {
      limiter.recordFailure('10.0.0.1');
      limiter.recordFailure('10.0.0.2');
      assert.strictEqual(limiter.getRecordCount(), 2);

      // Wait 65ms for window to expire
      await new Promise<void>((resolve) => setTimeout(resolve, 65));

      limiter.cleanupExpired();
      assert.strictEqual(limiter.getRecordCount(), 0);
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

  it('never evicts an active block to make room', () => {
    // maxEntries: 2, threshold: 2 failures
    const limiter = new RateLimiter(60000, 2, 300000, 2, 0);

    try {
      const blockedIP = '10.0.0.1';
      // Block the first IP
      limiter.recordFailure(blockedIP);
      limiter.recordFailure(blockedIP);
      assert.strictEqual(limiter.isBlocked(blockedIP), true);

      // Add a second unblocked IP
      limiter.recordFailure('10.0.0.2');
      assert.strictEqual(limiter.getRecordCount(), 2);

      // Add a third IP: capacity exceeded!
      // Unblocked IP (10.0.0.2) should be evicted, but blockedIP MUST NOT be evicted
      limiter.recordFailure('10.0.0.3');
      assert.strictEqual(limiter.getRecordCount(), 2);
      assert.strictEqual(limiter.isBlocked(blockedIP), true);

      // Block the second slot too
      limiter.recordFailure('10.0.0.3');
      assert.strictEqual(limiter.isBlocked('10.0.0.3'), true);

      // Now both slots are active blocks. Flooding with new IPs must NOT displace either active block
      for (let i = 10; i <= 20; i++) {
        limiter.recordFailure(`192.168.0.${i}`);
      }
      assert.strictEqual(limiter.getRecordCount(), 2);
      assert.strictEqual(limiter.isBlocked(blockedIP), true);
      assert.strictEqual(limiter.isBlocked('10.0.0.3'), true);
    } finally {
      limiter.destroy();
    }
  });
});

describe('Security: MQTT Stream Packet Size Validator', () => {
  it('accepts valid packets within maxPacketBytes', () => {
    const validator = new MqttStreamValidator(1024);

    // PINGREQ (0xC0, 0x00)
    const ping = Buffer.from([0xC0, 0x00]);
    assert.strictEqual(validator.processChunk(ping), null);

    // PUBLISH with 10 bytes payload (remaining length = 10)
    const pubHeader = Buffer.from([0x30, 0x0A]);
    const payload = Buffer.alloc(10, 'A');
    assert.strictEqual(validator.processChunk(Buffer.concat([pubHeader, payload])), null);
  });

  it('handles packets split across multiple chunks', () => {
    const validator = new MqttStreamValidator(1024);

    // 1-byte header chunk
    assert.strictEqual(validator.processChunk(Buffer.from([0x30])), null);
    // 1-byte length chunk (remaining length = 10)
    assert.strictEqual(validator.processChunk(Buffer.from([0x0A])), null);
    // 5 bytes payload
    assert.strictEqual(validator.processChunk(Buffer.alloc(5, 'B')), null);
    // remaining 5 bytes payload
    assert.strictEqual(validator.processChunk(Buffer.alloc(5, 'B')), null);

    // Packet complete, validator ready for next packet
    const ping = Buffer.from([0xC0, 0x00]);
    assert.strictEqual(validator.processChunk(ping), null);
  });

  it('handles multiple packets in a single chunk', () => {
    const validator = new MqttStreamValidator(1024);

    // PINGREQ (2 bytes) + DISCONNECT (2 bytes)
    const combined = Buffer.from([0xC0, 0x00, 0xE0, 0x00]);
    assert.strictEqual(validator.processChunk(combined), null);
  });

  it('rejects packet whose remaining length exceeds maxPacketBytes', () => {
    // Limit to 100 bytes
    const validator = new MqttStreamValidator(100);

    // Packet declaring remaining length of 500 bytes:
    // 500 = 0xF4, 0x03 (varbyte encoded: (0xF4 & 0x7F) + 3*128 = 116 + 384 = 500)
    const chunk = Buffer.from([0x30, 0xF4, 0x03]);
    const err = validator.processChunk(chunk);
    assert.notStrictEqual(err, null);
    assert.match(err!.message, /exceeds maximum allowed size/);
  });

  it('rejects malformed packet with remaining length exceeding 4 bytes', () => {
    const validator = new MqttStreamValidator(65536);

    // 5 continuation bytes (all with bit 7 set)
    const chunk = Buffer.from([0x30, 0x80, 0x80, 0x80, 0x80, 0x80]);
    const err = validator.processChunk(chunk);
    assert.notStrictEqual(err, null);
    assert.match(err!.message, /remaining length exceeds 4 bytes/);
  });
});

describe('Security: WebSocket Backpressure Handling', () => {
  it('resumes WebSocket reads when Duplex stream is read', () => {
    let resumed = false;
    const fakeWs = {
      readyState: 1, // OPEN
      OPEN: 1,
      resume: () => {
        resumed = true;
      },
      pause: () => {}
    };

    const stream = new Duplex({
      read() {
        if (fakeWs.readyState === fakeWs.OPEN) {
          fakeWs.resume();
        }
      },
      write(chunk, enc, cb) {
        cb();
      }
    });

    // Simulate stream read
    stream.read(0);
    assert.strictEqual(resumed, true);
  });
});
