import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Duplex } from 'stream';
import Aedes from 'aedes';
import { timingSafeCompare } from '../src/crypto-utils.js';
import { RateLimiter } from '../src/rate-limiter.js';
import { MqttStreamValidator } from '../src/mqtt-packet-validator.js';
import { AbuseDetector } from '../src/abuse-detector.js';
import { SysMetricsCollector } from '../src/sys-metrics.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { getAirportInfo } from 'airport-utils';

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

  it('blocks IP after reaching maxFailedConnections threshold and reports in getStats()', () => {
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

      const stats = limiter.getStats();
      assert.strictEqual(stats.trackedIPCount, 1);
      assert.strictEqual(stats.blockedIPCount, 1);
      assert.strictEqual(stats.totalBlocksIssued, 1);
      assert.strictEqual(stats.totalBlockedAttempts, 2); // 1 on block + 1 on isBlocked(testIP) check
      assert.strictEqual(stats.blockedIPs.length, 1);
      assert.strictEqual(stats.blockedIPs[0].ip, testIP);
      assert.strictEqual(stats.blockedIPs[0].failures, 3);
      assert.ok(stats.blockedIPs[0].remainingSeconds > 0);
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

describe('AbuseDetector: Built-in node:sqlite Persistence & Summary Telemetry', () => {
  it('persists and reloads client trust state across restarts, and tracks would_mute & regional stats', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-sqlite-test-'));
    const dbPath = join(tempDir, 'abuse.db');
    const config = {
      duplicateWindowSize: 100,
      duplicateWindowMs: 300000,
      duplicateThreshold: 10,
      maxDuplicatesPerPacket: 2,
      duplicateRateThreshold: 0.3,
      duplicateRateWindowMs: 300000,
      bucketCapacity: 20,
      bucketRefillRate: 3,
      maxPacketSize: 255,
      maxTopicsPerDay: 3,
      anomalyThreshold: 1,
      maxIataChanges24h: 3,
      topicHistorySize: 50,
      topicHistoryWindowMs: 86400000,
      persistencePath: dbPath,
      persistenceIntervalMs: 300000,
      stateRetentionMs: 604800000,
      enforcementEnabled: false,
    };

    try {
      const pubKey = 'A'.repeat(64);
      const detector1 = new AbuseDetector(config);
      detector1.initializeClient(pubKey, `v1_${pubKey}`, '198.51.100.1');
      const state1 = detector1.getClientStats(pubKey)!;
      detector1.checkIataChange(state1, 'SEA');

      // Record oversized raw packet to trigger anomaly & would_mute (since anomalyThreshold=1 and enforcementEnabled=false)
      const oversizedHex = 'FF'.repeat(300);
      detector1.recordPacket({ publicKey: pubKey }, { payload: Buffer.from(JSON.stringify({ origin_id: pubKey, raw: oversizedHex })) });

      const summary = detector1.getAllStats();
      assert.strictEqual(summary.trackedPublishers, 1);
      assert.strictEqual(summary.wouldMutePublishersCount, 1);
      assert.strictEqual(summary.anomalousPublishersCount, 1);
      assert.strictEqual(summary.activeByIata1h['SEA']?.activePublishers1h, 1);
      assert.strictEqual(summary.flaggedPublishers.length, 1);
      assert.strictEqual(summary.flaggedPublishers[0].status, 'would_mute');
      detector1.shutdown();

      const detector2 = new AbuseDetector(config);
      const state2 = detector2.getClientStats(pubKey);
      assert.ok(state2, 'Expected persisted client trust state to be reloaded');
      assert.strictEqual(state2?.publicKey, pubKey);
      assert.strictEqual(state2?.status, 'would_mute');
      assert.strictEqual(state2?.recentIPs[0]?.ip, '198.51.100.1');
      detector2.shutdown();
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('$SYS Telemetry: SysMetricsCollector', () => {
  it('formats uptime and publishes deduplicated retained $SYS/broker/# topics', () => {
    assert.strictEqual(SysMetricsCollector.formatUptime(45), '45s');
    assert.strictEqual(SysMetricsCollector.formatUptime(3665), '1h 1m 5s');
    assert.strictEqual(SysMetricsCollector.formatUptime(90061), '1d 1h 1m 1s');

    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-sys-test-'));
    const dbPath = join(tempDir, 'abuse.db');
    const aedes = new Aedes({ id: 'broker' });
    const limiter = new RateLimiter(60000, 5, 300000, 100, 0);
    const detector = new AbuseDetector({
      duplicateWindowSize: 100,
      duplicateWindowMs: 300000,
      duplicateThreshold: 10,
      maxDuplicatesPerPacket: 5,
      duplicateRateThreshold: 0.3,
      duplicateRateWindowMs: 300000,
      bucketCapacity: 20,
      bucketRefillRate: 3,
      maxPacketSize: 255,
      maxTopicsPerDay: 3,
      anomalyThreshold: 10,
      maxIataChanges24h: 3,
      topicHistorySize: 50,
      topicHistoryWindowMs: 86400000,
      persistencePath: dbPath,
      persistenceIntervalMs: 300000,
      stateRetentionMs: 604800000,
      enforcementEnabled: false,
    });

    const publishedTopics = new Map<string, string>();
    aedes.on('publish', (packet) => {
      if (packet.topic.startsWith('$SYS/broker/')) {
        publishedTopics.set(packet.topic, packet.payload.toString('utf-8'));
      }
    });

    const subscriberAccounts = new Map([
      ['admin', { roleName: 'admin', maxConnections: 10, activeConnections: new Set(['c1']) }],
    ]);

    const collector = new SysMetricsCollector({
      aedes,
      rateLimiter: limiter,
      abuseDetector: detector,
      subscriberAccounts,
      brokerVersion: '1.0.0',
      wsPort: 8883,
      tcpEnabled: true,
      tcpPort: 1883,
      intervalMs: 60000,
    });

    try {
      const pubKey = 'B'.repeat(64);
      detector.initializeClient(pubKey, `v1_${pubKey}`, '10.0.0.5');
      const state = detector.getClientStats(pubKey)!;
      detector.checkIataChange(state, 'PDX');
      detector.recordPacket({ publicKey: pubKey }, { payload: Buffer.from('{"origin_id":"' + pubKey + '"}') });

      collector.recordClientConnected(2);
      collector.recordAuthFailure();
      collector.recordUnauthorizedPublish();
      collector.recordStaleStatusFiltered();
      collector.recordPublish(`meshcore/PDX/${pubKey}/packets`, 128, false, true);
      collector.recordPublish(`meshcore/PDX/${pubKey}/status`, 64, false, true);
      collector.recordPublish(`meshcore/PDX/${pubKey}/internal`, 256, true, false);

      collector.publishSnapshot();

      assert.ok(publishedTopics.has('$SYS/broker/summary'));
      assert.ok(publishedTopics.has('$SYS/broker/system'));
      assert.ok(publishedTopics.has('$SYS/broker/clients'));
      assert.ok(publishedTopics.has('$SYS/broker/regions'));
      assert.ok(publishedTopics.has('$SYS/broker/regions/PDX'));
      assert.ok(publishedTopics.has('$SYS/broker/traffic'));
      assert.ok(publishedTopics.has('$SYS/broker/security'));

      assert.strictEqual(publishedTopics.get('$SYS/broker/traffic/messages/received'), '2');
      assert.strictEqual(publishedTopics.get('$SYS/broker/traffic/messages/bytes_received'), '192');
      assert.strictEqual(publishedTopics.get('$SYS/broker/traffic/by_subtopic/packets'), '1');
      assert.strictEqual(publishedTopics.get('$SYS/broker/traffic/by_subtopic/status'), '1');
      assert.strictEqual(publishedTopics.get('$SYS/broker/traffic/by_subtopic/internal'), '1');
      assert.strictEqual(publishedTopics.get('$SYS/broker/traffic/stale_status_filtered'), '1');
      assert.strictEqual(publishedTopics.get('$SYS/broker/security/auth_failures'), '1');
      assert.strictEqual(publishedTopics.get('$SYS/broker/security/unauthorized_publishes'), '1');
      assert.strictEqual(publishedTopics.get('$SYS/broker/system/retained_messages'), '1');
    } finally {
      collector.stop();
      limiter.destroy();
      detector.shutdown();
      aedes.close();
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});

describe('Dependencies & End-to-End Compiled Broker (dist/server.js)', () => {
  it('validates IATA airport codes with updated airport-utils', () => {
    const sea = getAirportInfo('SEA');
    assert.ok(sea);
    assert.throws(() => getAirportInfo('ZZZ'));
  });

  it('starts compiled dist/server.js, serves /health, authenticates Admin over TCP, and delivers retained $SYS/broker/summary', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-e2e-test-'));
    const dbPath = join(tempDir, 'abuse.db');
    const wsPort = 18883;
    const tcpPort = 11883;

    const child = spawn(process.execPath, ['dist/server.js'], {
      env: {
        ...process.env,
        MQTT_WS_PORT: String(wsPort),
        MQTT_TCP_PORT: String(tcpPort),
        ENABLE_TCP_MQTT: 'true',
        MQTT_HOST: '127.0.0.1',
        AUTH_EXPECTED_AUDIENCE: 'test.local',
        HTTP_REDIRECT_URL: '',
        MQTT_MAX_PACKET_BYTES: '65536',
        MQTT_SYS_INTERVAL_MS: '10000',
        SUBSCRIBER_MAX_CONNECTIONS_DEFAULT: '2',
        SUBSCRIBER_1: 'admin:testpass123:1:2',
        ABUSE_ENFORCEMENT_ENABLED: 'false',
        ABUSE_DUPLICATE_WINDOW_SIZE: '100',
        ABUSE_DUPLICATE_WINDOW_MS: '300000',
        ABUSE_DUPLICATE_THRESHOLD: '10',
        ABUSE_MAX_DUPLICATES_PER_PACKET: '5',
        ABUSE_DUPLICATE_RATE_THRESHOLD: '0.3',
        ABUSE_DUPLICATE_RATE_WINDOW_MS: '300000',
        ABUSE_BUCKET_CAPACITY: '20',
        ABUSE_BUCKET_REFILL_RATE: 3 as any,
        ABUSE_MAX_PACKET_SIZE: '255',
        ABUSE_MAX_TOPICS_PER_DAY: '3',
        ABUSE_ANOMALY_THRESHOLD: '10',
        ABUSE_MAX_IATA_CHANGES_24H: '3',
        ABUSE_TOPIC_HISTORY_SIZE: '50',
        ABUSE_TOPIC_HISTORY_WINDOW_MS: '86400000',
        ABUSE_PERSISTENCE_PATH: dbPath,
        ABUSE_PERSISTENCE_INTERVAL_MS: '300000',
        ABUSE_STATE_RETENTION_MS: '604800000',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    try {
      // Wait for broker to print listening message
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Broker startup timed out')), 5000);
        let output = '';
        child.stdout.on('data', (chunk) => {
          output += chunk.toString();
          if (output.includes('Ready to accept connections') && output.includes('TCP MQTT listening on')) {
            clearTimeout(timeout);
            resolve();
          }
        });
        child.stderr.on('data', (chunk) => {
          output += chunk.toString();
        });
        child.on('exit', (code) => {
          clearTimeout(timeout);
          reject(new Error(`Broker exited prematurely with code ${code}: ${output}`));
        });
      });

      // 1. Verify /health endpoint returns 200 OK
      const healthRes = await fetch(`http://127.0.0.1:${wsPort}/health`);
      assert.strictEqual(healthRes.status, 200);
      assert.strictEqual(await healthRes.text(), '{"status":"ok","service":"MeshCore MQTT Broker"}');

      // 2. Verify MQTT TCP connection with Admin subscriber credentials and subscribe to $SYS/broker/summary
      const sysSummaryPayload = await new Promise<string>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timed out waiting for retained $SYS/broker/summary')), 4000);
        let stage: 'connecting' | 'subscribing' = 'connecting';
        let receivedBuf = Buffer.alloc(0);

        const socket = createConnection({ host: '127.0.0.1', port: tcpPort }, () => {
          // Build MQTT 3.1.1 CONNECT packet with username="admin", password="testpass123"
          const vh = Buffer.from([
            0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, // Protocol Name "MQTT"
            0x04,                               // Protocol Level 4 (3.1.1)
            0xc2,                               // Connect Flags: Username + Password + CleanSession
            0x00, 0x3c,                         // Keep Alive 60s
          ]);
          const clientId = Buffer.from([0x00, 0x07, ...Buffer.from('testsub')]);
          const user = Buffer.from([0x00, 0x05, ...Buffer.from('admin')]);
          const pass = Buffer.from([0x00, 0x0b, ...Buffer.from('testpass123')]);
          const body = Buffer.concat([vh, clientId, user, pass]);
          const packet = Buffer.concat([Buffer.from([0x10, body.length]), body]);
          socket.write(packet);
        });

        socket.on('data', (data) => {
          receivedBuf = Buffer.concat([receivedBuf, data]);

          if (stage === 'connecting' && receivedBuf.length >= 4) {
            assert.strictEqual(receivedBuf[0], 0x20, 'Expected CONNACK packet');
            assert.strictEqual(receivedBuf[3], 0x00, 'Expected CONNACK 0x00 (Connection Accepted)');
            receivedBuf = receivedBuf.slice(4);
            stage = 'subscribing';

            // Send SUBSCRIBE packet (0x82) for topic "$SYS/broker/summary"
            const topicBytes = Buffer.from('$SYS/broker/summary', 'utf-8');
            const subBody = Buffer.concat([
              Buffer.from([0x00, 0x01]), // Packet Identifier = 1
              Buffer.from([0x00, topicBytes.length]),
              topicBytes,
              Buffer.from([0x00]), // Requested QoS 0
            ]);
            socket.write(Buffer.concat([Buffer.from([0x82, subBody.length]), subBody]));
          }

          if (stage === 'subscribing') {
            const str = receivedBuf.toString('utf-8');
            const jsonStart = str.indexOf('{"timestamp":');
            if (jsonStart !== -1 && str.includes('"retainedMessages":')) {
              clearTimeout(timeout);
              socket.destroy();
              resolve(str.slice(jsonStart));
            }
          }
        });

        socket.on('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      });

      const parsedSummary = JSON.parse(sysSummaryPayload);
      assert.ok(parsedSummary.version.includes('meshcore-mqtt-broker'));
      assert.strictEqual(typeof parsedSummary.uptimeSeconds, 'number');
      assert.ok(parsedSummary.clients);
      assert.ok(parsedSummary.traffic);
      assert.ok(parsedSummary.security);
    } finally {
      child.kill();
      await new Promise((resolve) => child.once('exit', resolve));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
