import { describe, it } from 'node:test';
import assert from 'node:assert';
import Aedes from 'aedes';
import { RateLimiter } from '../src/rate-limiter.js';
import { AbuseDetector } from '../src/abuse-detector.js';
import { SysMetricsCollector, describeWsCloseCode } from '../src/sys-metrics.js';
import { loadMqttConfig } from '../src/config.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('Connection Tolerance & Disconnect Diagnostics', () => {
  it('RateLimiter prevents observer or other-user logins from wiping admin credential failures', () => {
    const limiter = new RateLimiter(60000, 3, 300000, 100, 0, 10000);
    const now = Date.now();
    const observerUser = `v1_${'A'.repeat(64)}`;

    // 2 failed admin logins
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.1', 'admin', now), false);
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.1', 'admin', now + 100), false);

    // Self-signed observer login and low-privilege viewer login must NOT decay admin's failures
    limiter.recordSuccess('10.0.0.1', observerUser, now + 200);
    limiter.recordSuccess('10.0.0.1', 'viewer1', now + 300);

    // 3rd failed admin attempt still triggers IP block
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.1', 'admin', now + 400), true);
    assert.strictEqual(limiter.isBlocked('10.0.0.1', now + 450), true);

    // Active block cannot be cleared by recordSuccess
    limiter.recordSuccess('10.0.0.1', 'admin', now + 500);
    assert.strictEqual(limiter.isBlocked('10.0.0.1', now + 550), true);
  });

  it('RateLimiter decays same-username auth failures and cooldown-throttles pre-auth drop decay', () => {
    const limiter = new RateLimiter(60000, 3, 300000, 100, 0, 10000);
    const now = Date.now();

    // 2 failed admin logins, then 1 successful admin login -> decays count from 2 to 1
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.2', 'admin', now), false);
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.2', 'admin', now + 50), false);
    limiter.recordSuccess('10.0.0.2', 'admin', now + 100);

    // Next failure brings count back to 2 (not blocked yet); the one after (3) blocks
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.2', 'admin', now + 200), false);
    assert.strictEqual(limiter.recordAuthFailure('10.0.0.2', 'admin', now + 300), true);

    // Pre-auth socket drops decay by 1 at most once per 10s cooldown
    assert.strictEqual(limiter.recordFailure('10.0.0.3', now), false); // count=1
    assert.strictEqual(limiter.recordFailure('10.0.0.3', now + 100), false); // count=2
    limiter.recordSuccess('10.0.0.3', 'v1_obs', now + 200); // decays count to 1, sets lastDecayAt=now+200
    // Immediate second login within <10s must NOT decay again
    limiter.recordSuccess('10.0.0.3', 'v1_obs', now + 500); // count still 1
    assert.strictEqual(limiter.recordFailure('10.0.0.3', now + 600), false); // count=2
    // After 10s cooldown elapses, decay works again (2 -> 1), so next failure hits 2 instead of blocking at 3
    limiter.recordSuccess('10.0.0.3', 'v1_obs', now + 10200); // count=1
    assert.strictEqual(limiter.recordFailure('10.0.0.3', now + 10300), false); // count=2
    assert.strictEqual(limiter.recordFailure('10.0.0.3', now + 10400), true); // count=3 -> blocked
  });

  it('SysMetricsCollector tracks 1006/1009/1001/clean_disconnect and backfills late WS close codes', async () => {
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

      const obsKey = 'A'.repeat(64);
      sysMetrics.recordConnectionError();
      sysMetrics.recordClientDisconnected({
        clientId: 'obs-1',
        clientType: 'publisher',
        publicKey: obsKey,
        ip: '1.2.3.4',
        transport: 'websocket',
        durationSeconds: 5,
        reason: 'abnormal_close_1006',
        wsCloseCode: 1006,
      });
      sysMetrics.recordClientDisconnected({
        clientId: 'obs-1',
        clientType: 'publisher',
        publicKey: obsKey,
        ip: '1.2.3.4',
        transport: 'websocket',
        durationSeconds: 45,
        reason: 'payload_too_big_1009',
        wsCloseCode: 1009,
      });
      sysMetrics.recordClientDisconnected({
        clientId: 'sub-1',
        clientType: 'subscriber',
        username: 'viewer1',
        ip: '5.6.7.8',
        transport: 'websocket',
        durationSeconds: 400,
        reason: 'clean_disconnect',
      });
      // Simulate late ws.on('close') firing after clientDisconnect
      sysMetrics.recordLateWsCloseCode('viewer1', 1000);

      sysMetrics.recordClientDisconnected({
        clientId: 'sub-2',
        clientType: 'subscriber',
        username: 'viewer2',
        ip: '5.6.7.9',
        transport: 'websocket',
        durationSeconds: 120,
        reason: 'going_away_1001',
        wsCloseCode: 1001,
      });

      const snap = sysMetrics.getDisconnectSnapshot();
      assert.strictEqual(snap.total, 4);
      assert.strictEqual(snap.connectionErrors, 1);
      assert.strictEqual(snap.avgDurationSeconds, 142.5);
      assert.strictEqual(snap.byReason.abnormal_close_1006, 1);
      assert.strictEqual(snap.byReason.payload_too_big_1009, 1);
      assert.strictEqual(snap.byReason.going_away_1001, 1);
      assert.strictEqual(snap.byReason.clean_disconnect, 1);
      assert.strictEqual(snap.wsCloseCodes['1006'], 1);
      assert.strictEqual(snap.wsCloseCodes['1009'], 1);
      assert.strictEqual(snap.wsCloseCodes['1000'], 1);
      assert.strictEqual(snap.wsCloseCodes['1001'], 1);
      assert.strictEqual(snap.wsCloseCodeMeanings['1006'], describeWsCloseCode(1006));
      assert.strictEqual(snap.wsCloseCodeMeanings['1009'], describeWsCloseCode(1009));
      assert.strictEqual(snap.sessionDurations.under10s, 1);
      assert.strictEqual(snap.sessionDurations.under60s, 1);
      assert.strictEqual(snap.sessionDurations.under5m, 1);
      assert.strictEqual(snap.sessionDurations.over5m, 1);

      const obsChurn = snap.topChurning.find((c) => c.publicKey === obsKey)!;
      assert.ok(obsChurn);
      assert.strictEqual(obsChurn.disconnectCount, 2);
      assert.strictEqual(obsChurn.shortSessionCount, 2);
      assert.strictEqual(obsChurn.abnormal1006Count, 1);
      assert.strictEqual(obsChurn.payload1009Count, 1);
      assert.strictEqual(obsChurn.lastReason, 'payload_too_big_1009');
      assert.strictEqual(obsChurn.lastWsCloseCode, 1009);
      assert.strictEqual(obsChurn.lastWsCloseMeaning, describeWsCloseCode(1009));

      const viewerChurn = snap.topChurning.find((c) => c.clientId === 'sub-1')!;
      assert.ok(viewerChurn);
      assert.strictEqual(viewerChurn.lastWsCloseCode, 1000);
      assert.strictEqual(viewerChurn.lastWsCloseMeaning, describeWsCloseCode(1000));
    } finally {
      if (abuseDetector) await abuseDetector.shutdown();
      if (aedes) await new Promise<void>((resolve) => aedes!.close(() => resolve()));
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('loadMqttConfig enforces connectTimeout floor, WS ping timeout validation, and defaults', () => {
    const prevEnv = {
      MQTT_WS_PORT: process.env.MQTT_WS_PORT,
      MQTT_HOST: process.env.MQTT_HOST,
      AUTH_EXPECTED_AUDIENCE: process.env.AUTH_EXPECTED_AUDIENCE,
      MQTT_CONNECT_TIMEOUT_MS: process.env.MQTT_CONNECT_TIMEOUT_MS,
      MQTT_WS_PING_INTERVAL_MS: process.env.MQTT_WS_PING_INTERVAL_MS,
      MQTT_WS_PING_TIMEOUT_MS: process.env.MQTT_WS_PING_TIMEOUT_MS,
      MQTT_TCP_KEEPALIVE_MS: process.env.MQTT_TCP_KEEPALIVE_MS,
      MQTT_MAX_UNAUTH_CONNECTIONS_PER_IP: process.env.MQTT_MAX_UNAUTH_CONNECTIONS_PER_IP,
    };

    try {
      process.env.MQTT_WS_PORT = '8883';
      process.env.MQTT_HOST = '127.0.0.1';
      process.env.AUTH_EXPECTED_AUDIENCE = '';
      delete process.env.MQTT_CONNECT_TIMEOUT_MS;
      delete process.env.MQTT_WS_PING_INTERVAL_MS;
      delete process.env.MQTT_WS_PING_TIMEOUT_MS;
      delete process.env.MQTT_TCP_KEEPALIVE_MS;
      delete process.env.MQTT_MAX_UNAUTH_CONNECTIONS_PER_IP;

      const defaults = loadMqttConfig();
      assert.strictEqual(defaults.connectTimeoutMs, 30000);
      assert.strictEqual(defaults.wsPingIntervalMs, 30000);
      assert.strictEqual(defaults.wsPingTimeoutMs, 90000);
      assert.strictEqual(defaults.tcpKeepaliveMs, 30000);
      assert.strictEqual(defaults.maxUnauthConnectionsPerIp, 100);

      // Setting 0 or <5000 clamps connectTimeoutMs to 5000ms; wsPingTimeout <= interval auto-adjusts to 3x
      process.env.MQTT_CONNECT_TIMEOUT_MS = '0';
      process.env.MQTT_WS_PING_INTERVAL_MS = '20000';
      process.env.MQTT_WS_PING_TIMEOUT_MS = '10000';
      process.env.MQTT_TCP_KEEPALIVE_MS = '15000';
      process.env.MQTT_MAX_UNAUTH_CONNECTIONS_PER_IP = '25';

      const clamped = loadMqttConfig();
      assert.strictEqual(clamped.connectTimeoutMs, 5000);
      assert.strictEqual(clamped.wsPingIntervalMs, 20000);
      assert.strictEqual(clamped.wsPingTimeoutMs, 60000);
      assert.strictEqual(clamped.tcpKeepaliveMs, 15000);
      assert.strictEqual(clamped.maxUnauthConnectionsPerIp, 25);

      process.env.MQTT_CONNECT_TIMEOUT_MS = '45000';
      process.env.MQTT_WS_PING_INTERVAL_MS = '0';
      process.env.MQTT_WS_PING_TIMEOUT_MS = '120000';

      const overrides = loadMqttConfig();
      assert.strictEqual(overrides.connectTimeoutMs, 45000);
      assert.strictEqual(overrides.wsPingIntervalMs, 0);
      assert.strictEqual(overrides.wsPingTimeoutMs, 120000);
    } finally {
      for (const [k, v] of Object.entries(prevEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });
});
