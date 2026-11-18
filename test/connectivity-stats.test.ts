import { describe, it } from 'node:test';
import assert from 'node:assert';
import Aedes from 'aedes';
import { RateLimiter } from '../src/rate-limiter.js';
import { AbuseDetector } from '../src/abuse-detector.js';
import { SysMetricsCollector } from '../src/sys-metrics.js';
import { loadMqttConfig } from '../src/config.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('Connection Tolerance & Disconnect Diagnostics', () => {
  it('RateLimiter.recordSuccess clears transient failures while preserving active blocks', () => {
    const limiter = new RateLimiter(60000, 3, 300000, 100, 0);

    // 2 failures (below block threshold of 3)
    assert.strictEqual(limiter.recordFailure('10.0.0.1'), false);
    assert.strictEqual(limiter.recordFailure('10.0.0.1'), false);
    assert.strictEqual(limiter.getStats().trackedIPCount, 1);

    // Successful auth clears transient failure record
    limiter.recordSuccess('10.0.0.1');
    assert.strictEqual(limiter.getStats().trackedIPCount, 0);

    // Next 2 failures start fresh and do not immediately block
    assert.strictEqual(limiter.recordFailure('10.0.0.1'), false);
    assert.strictEqual(limiter.recordFailure('10.0.0.1'), false);

    // 3rd failure triggers block; recordSuccess must NOT clear an active block
    assert.strictEqual(limiter.recordFailure('10.0.0.1'), true);
    limiter.recordSuccess('10.0.0.1');
    assert.strictEqual(limiter.isBlocked('10.0.0.1'), true);
  });

  it('SysMetricsCollector tracks disconnect reasons, durations, WS close codes, and top churning clients', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'meshcore-conn-stats-'));
    let aedes: Aedes | undefined;
    let abuseDetector: AbuseDetector | undefined;
    try {
      aedes = new Aedes({ id: 'broker-test' });
      const rateLimiter = new RateLimiter(60000, 10, 300000, 100, 0);
      abuseDetector = new AbuseDetector({
        duplicateWindowSize: 50,
        duplicateWindowMs: 60000,
        duplicateThreshold: 3,
        maxDuplicatesPerPacket: 5,
        duplicateRateThreshold: 0.3,
        duplicateRateWindowMs: 300000,
        bucketCapacity: 100,
        bucketRefillRate: 10,
        maxPacketSize: 8192,
        maxTopicsPerDay: 50,
        anomalyThreshold: 10,
        maxIataChanges24h: 3,
        topicHistorySize: 20,
        topicHistoryWindowMs: 3600000,
        persistencePath: join(tmpDir, 'abuse.json'),
        persistenceIntervalMs: 0,
        enforcementEnabled: false,
        muteDurationMs: 14400000,
      });

      const sysMetrics = new SysMetricsCollector({
        aedes,
        rateLimiter,
        abuseDetector,
        subscriberAccounts: new Map(),
        brokerVersion: '1.1.0-test',
        wsPort: 8883,
        tcpEnabled: false,
        tcpPort: 1883,
      });

      sysMetrics.recordConnectionError();
      sysMetrics.recordClientDisconnected({
        clientId: 'obs-1',
        clientType: 'publisher',
        publicKey: 'A'.repeat(64),
        ip: '1.2.3.4',
        transport: 'websocket',
        durationSeconds: 5,
        reason: 'keepalive_timeout',
        wsCloseCode: 1006,
      });
      sysMetrics.recordClientDisconnected({
        clientId: 'obs-1',
        clientType: 'publisher',
        publicKey: 'A'.repeat(64),
        ip: '1.2.3.4',
        transport: 'websocket',
        durationSeconds: 45,
        reason: 'ws_ping_timeout',
        wsCloseCode: 1006,
      });
      sysMetrics.recordClientDisconnected({
        clientId: 'sub-1',
        clientType: 'subscriber',
        username: 'viewer1',
        ip: '5.6.7.8',
        transport: 'websocket',
        durationSeconds: 400,
        reason: 'clean_disconnect',
        wsCloseCode: 1000,
      });

      const snap = sysMetrics.getDisconnectSnapshot();
      assert.strictEqual(snap.total, 3);
      assert.strictEqual(snap.connectionErrors, 1);
      assert.strictEqual(snap.avgDurationSeconds, 150);
      assert.strictEqual(snap.byReason.keepalive_timeout, 1);
      assert.strictEqual(snap.byReason.ws_ping_timeout, 1);
      assert.strictEqual(snap.byReason.clean_disconnect, 1);
      assert.strictEqual(snap.wsCloseCodes['1006'], 2);
      assert.strictEqual(snap.wsCloseCodes['1000'], 1);
      assert.strictEqual(snap.sessionDurations.under10s, 1);
      assert.strictEqual(snap.sessionDurations.under60s, 1);
      assert.strictEqual(snap.sessionDurations.over5m, 1);
      assert.strictEqual(snap.topChurning.length, 2);
      assert.strictEqual(snap.topChurning[0].publicKey, 'A'.repeat(64));
      assert.strictEqual(snap.topChurning[0].disconnectCount, 2);
      assert.strictEqual(snap.topChurning[0].shortSessionCount, 2);
      assert.strictEqual(snap.topChurning[0].lastReason, 'ws_ping_timeout');
    } finally {
      if (abuseDetector) await abuseDetector.shutdown();
      if (aedes) await new Promise<void>((resolve) => aedes!.close(() => resolve()));
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('loadMqttConfig parses connection tolerance env vars with defaults and overrides', () => {
    const prevEnv = {
      MQTT_WS_PORT: process.env.MQTT_WS_PORT,
      MQTT_HOST: process.env.MQTT_HOST,
      AUTH_EXPECTED_AUDIENCE: process.env.AUTH_EXPECTED_AUDIENCE,
      MQTT_CONNECT_TIMEOUT_MS: process.env.MQTT_CONNECT_TIMEOUT_MS,
      MQTT_WS_PING_INTERVAL_MS: process.env.MQTT_WS_PING_INTERVAL_MS,
      MQTT_WS_PING_TIMEOUT_MS: process.env.MQTT_WS_PING_TIMEOUT_MS,
      MQTT_TCP_KEEPALIVE_MS: process.env.MQTT_TCP_KEEPALIVE_MS,
    };

    try {
      process.env.MQTT_WS_PORT = '8883';
      process.env.MQTT_HOST = '127.0.0.1';
      process.env.AUTH_EXPECTED_AUDIENCE = '';
      delete process.env.MQTT_CONNECT_TIMEOUT_MS;
      delete process.env.MQTT_WS_PING_INTERVAL_MS;
      delete process.env.MQTT_WS_PING_TIMEOUT_MS;
      delete process.env.MQTT_TCP_KEEPALIVE_MS;

      const defaults = loadMqttConfig();
      assert.strictEqual(defaults.connectTimeoutMs, 60000);
      assert.strictEqual(defaults.wsPingIntervalMs, 30000);
      assert.strictEqual(defaults.wsPingTimeoutMs, 90000);
      assert.strictEqual(defaults.tcpKeepaliveMs, 30000);

      process.env.MQTT_CONNECT_TIMEOUT_MS = '45000';
      process.env.MQTT_WS_PING_INTERVAL_MS = '0';
      process.env.MQTT_WS_PING_TIMEOUT_MS = '120000';
      process.env.MQTT_TCP_KEEPALIVE_MS = '15000';

      const overrides = loadMqttConfig();
      assert.strictEqual(overrides.connectTimeoutMs, 45000);
      assert.strictEqual(overrides.wsPingIntervalMs, 0);
      assert.strictEqual(overrides.wsPingTimeoutMs, 120000);
      assert.strictEqual(overrides.tcpKeepaliveMs, 15000);
    } finally {
      for (const [k, v] of Object.entries(prevEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });
});
