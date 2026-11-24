import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createServer } from 'node:net';
import { spawn, ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import crypto from 'node:crypto';
import WebSocket from 'ws';
import mqttPacket from 'mqtt-packet';
import { derivePeerKeyPair, createPeerJwt } from '../src/peer-crypto.js';
import { validatePeerPacket } from '../src/peer-bridge.js';
import { ObserverRegionBlocklist } from '../src/region-filter.js';
import { loadMqttConfig, MAX_LWT_GRACE_MS } from '../src/config.js';

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
    srv.on('error', reject);
  });
}

interface ReceivedMqttMessage {
  topic: string;
  payload: string;
  retain: boolean;
}

interface MqttWsClient {
  ws: WebSocket;
  received: ReceivedMqttMessage[];
  getPongCount: () => number;
  publish: (topic: string, payload: string, retain?: boolean) => Promise<void>;
  subscribe: (topic: string) => Promise<number[]>;
  waitForClose: (timeoutMs?: number) => Promise<void>;
  waitForMessage: (
    predicate: (msg: ReceivedMqttMessage) => boolean,
    timeoutMs?: number
  ) => Promise<ReceivedMqttMessage>;
  close: () => void;
}

async function connectMqttWsClient(
  url: string,
  clientId: string,
  username: string,
  password: string,
  will?: { topic: string; payload: Buffer; qos: 0 | 1 | 2; retain: boolean }
): Promise<MqttWsClient> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, ['mqtt']);
    const parser = mqttPacket.parser({ protocolVersion: 4 });
    const received: ReceivedMqttMessage[] = [];
    let pongCount = 0;
    let subWaiter: ((granted: number[]) => void) | null = null;
    let subRejecter: ((err: Error) => void) | null = null;
    let connected = false;
    let isClosed = false;
    const closeListeners: Array<() => void> = [];
    const msgListeners: Array<() => void> = [];

    const timeout = setTimeout(() => {
      ws.terminate();
      reject(new Error(`Timed out connecting MQTT WS client ${clientId} to ${url}`));
    }, 8000);

    ws.on('pong', () => {
      pongCount++;
    });

    ws.on('close', () => {
      isClosed = true;
      if (subRejecter) {
        const rej = subRejecter;
        subWaiter = null;
        subRejecter = null;
        rej(new Error(`WebSocket closed before SUBACK for ${clientId}`));
      }
      for (const fn of closeListeners) fn();
    });

    parser.on('packet', (packet: any) => {
      if (packet.cmd === 'connack') {
        clearTimeout(timeout);
        if (packet.returnCode !== 0) {
          ws.close();
          const err: any = new Error(`CONNACK refused with code ${packet.returnCode} for ${clientId}`);
          err.returnCode = packet.returnCode;
          reject(err);
          return;
        }
        connected = true;
        resolve({
          ws,
          received,
          getPongCount: () => pongCount,
          publish: (topic: string, payload: string, retain: boolean = false) =>
            new Promise<void>((res, rej) => {
              const buf = mqttPacket.generate({
                cmd: 'publish',
                topic,
                payload: Buffer.from(payload, 'utf-8'),
                qos: 0,
                retain,
                dup: false,
              });
              ws.send(buf, (err) => (err ? rej(err) : res()));
            }),
          subscribe: (topic: string) =>
            new Promise<number[]>((res, rej) => {
              if (isClosed || ws.readyState === WebSocket.CLOSED) {
                rej(new Error(`WebSocket already closed before subscribe for ${clientId}`));
                return;
              }
              subWaiter = res;
              subRejecter = rej;
              const buf = mqttPacket.generate({
                cmd: 'subscribe',
                messageId: 1,
                subscriptions: [{ topic, qos: 0 }],
              });
              ws.send(buf, (err) => {
                if (err) {
                  subWaiter = null;
                  subRejecter = null;
                  rej(err);
                }
              });
            }),
          waitForClose: (timeoutMs = 3000) =>
            new Promise<void>((res, rej) => {
              if (isClosed || ws.readyState === WebSocket.CLOSED) {
                res();
                return;
              }
              const timer = setTimeout(
                () => rej(new Error(`Timed out waiting for ${clientId} to close`)),
                timeoutMs
              );
              closeListeners.push(() => {
                clearTimeout(timer);
                res();
              });
            }),
          waitForMessage: (predicate, timeoutMs = 3000) =>
            new Promise<ReceivedMqttMessage>((res, rej) => {
              const existing = received.find(predicate);
              if (existing) {
                res(existing);
                return;
              }
              const timer = setTimeout(() => {
                const idx = msgListeners.indexOf(check);
                if (idx >= 0) msgListeners.splice(idx, 1);
                rej(new Error(`Timed out waiting for expected message on ${clientId}`));
              }, timeoutMs);
              const check = () => {
                const match = received.find(predicate);
                if (match) {
                  clearTimeout(timer);
                  const idx = msgListeners.indexOf(check);
                  if (idx >= 0) msgListeners.splice(idx, 1);
                  res(match);
                }
              };
              msgListeners.push(check);
            }),
          close: () => {
            try {
              ws.close();
            } catch {}
          },
        });
      } else if (packet.cmd === 'suback') {
        if (subWaiter) {
          const cb = subWaiter;
          subWaiter = null;
          subRejecter = null;
          cb(packet.granted || []);
        }
      } else if (packet.cmd === 'publish') {
        received.push({
          topic: packet.topic,
          payload: packet.payload.toString('utf-8'),
          retain: Boolean(packet.retain),
        });
        for (const fn of [...msgListeners]) fn();
      }
    });

    ws.on('open', () => {
      const connectPacket: any = {
        cmd: 'connect',
        protocolId: 'MQTT',
        protocolVersion: 4,
        clean: true,
        keepalive: 30,
        clientId,
        username,
        password: Buffer.from(password, 'utf-8'),
      };
      if (will) {
        connectPacket.will = will;
      }
      ws.send(mqttPacket.generate(connectPacket));
    });

    ws.on('message', (data) => {
      const buf = Buffer.isBuffer(data)
        ? data
        : Array.isArray(data)
          ? Buffer.concat(data)
          : Buffer.from(data);
      parser.parse(buf);
    });

    ws.on('error', (err) => {
      if (!connected) {
        clearTimeout(timeout);
        reject(err);
      }
    });
  });
}

async function spawnBroker(
  name: string,
  wsPort: number,
  audience: string,
  tempDir: string,
  extraEnv: Record<string, string> = {}
): Promise<{ proc: ChildProcess; logs: () => string }> {
  const dbPath = join(tempDir, `${name}-abuse.db`);
  let output = '';

  const env: Record<string, string | undefined> = {
    ...process.env,
    LOG_LEVEL: 'debug',
    MQTT_WS_PORT: String(wsPort),
    MQTT_TCP_PORT: String(wsPort + 1000),
    ENABLE_TCP_MQTT: 'false',
    MQTT_HOST: '127.0.0.1',
    AUTH_EXPECTED_AUDIENCE: audience,
    HTTP_REDIRECT_URL: '',
    MQTT_MAX_PACKET_BYTES: '65536',
    MQTT_SYS_INTERVAL_MS: '60000',
    SUBSCRIBER_MAX_CONNECTIONS_DEFAULT: '10',
    SUBSCRIBER_1: 'admin:adminpass123:1:10',
    ABUSE_ENFORCEMENT_ENABLED: 'false',
    ABUSE_DUPLICATE_WINDOW_SIZE: '100',
    ABUSE_DUPLICATE_WINDOW_MS: '300000',
    ABUSE_DUPLICATE_THRESHOLD: '10',
    ABUSE_MAX_DUPLICATES_PER_PACKET: '5',
    ABUSE_DUPLICATE_RATE_THRESHOLD: '0.3',
    ABUSE_DUPLICATE_RATE_WINDOW_MS: '300000',
    ABUSE_BUCKET_CAPACITY: '50',
    ABUSE_BUCKET_REFILL_RATE: '10',
    ABUSE_MAX_PACKET_SIZE: '255',
    ABUSE_MAX_TOPICS_PER_DAY: '3',
    ABUSE_ANOMALY_THRESHOLD: '10',
    ABUSE_MAX_IATA_CHANGES_24H: '3',
    ABUSE_TOPIC_HISTORY_SIZE: '50',
    ABUSE_TOPIC_HISTORY_WINDOW_MS: '86400000',
    ABUSE_PERSISTENCE_PATH: dbPath,
    ABUSE_PERSISTENCE_INTERVAL_MS: '300000',
    ABUSE_STATE_RETENTION_MS: '604800000',
  };

  delete env.ALLOWED_REGIONS;
  Object.assign(env, extraEnv);

  const proc = spawn(process.execPath, ['dist/server.js'], {
    env: env as NodeJS.ProcessEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Broker ${name} startup timed out: ${output}`)), 8000);
    proc.stdout?.on('data', (chunk) => {
      output += chunk.toString();
      if (output.includes('Ready to accept connections')) {
        clearTimeout(timeout);
        resolve();
      }
    });
    proc.stderr?.on('data', (chunk) => {
      output += chunk.toString();
    });
    proc.on('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`Broker ${name} exited prematurely with code ${code}: ${output}`));
    });
  });

  return { proc, logs: () => output };
}

describe('Observer Compatibility: Unit Tests', () => {
  const validPubKey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';

  it('allows missing origin_id on slim /packets in validatePeerPacket, while keeping strict checks on /status and mismatches', () => {
    const slimPacket = JSON.stringify({
      type: 'PACKET',
      direction: 'rx',
      raw: '1500AA1122',
    });
    const resPackets = validatePeerPacket(
      `meshcore/SEA/${validPubKey.toLowerCase()}/packets`,
      Buffer.from(slimPacket),
      (code) => code === 'SEA'
    );
    assert.strictEqual(resPackets.valid, true);
    assert.strictEqual(resPackets.originId, validPubKey);
    assert.strictEqual(resPackets.normalizedTopic, `meshcore/SEA/${validPubKey}/packets`);
    assert.strictEqual(resPackets.parsedMessage.origin_id, validPubKey);
    assert.ok(resPackets.enrichedPayload);
    assert.strictEqual(JSON.parse(resPackets.enrichedPayload.toString('utf-8')).origin_id, validPubKey);

    const missingOnStatus = validatePeerPacket(
      `meshcore/SEA/${validPubKey}/status`,
      Buffer.from(JSON.stringify({ status: 'online' })),
      (code) => code === 'SEA'
    );
    assert.strictEqual(missingOnStatus.valid, false);
    assert.match(missingOnStatus.error!, /valid 64-hex origin_id/);

    const mismatchOnPackets = validatePeerPacket(
      `meshcore/SEA/${validPubKey}/packets`,
      Buffer.from(JSON.stringify({ origin_id: 'F'.repeat(64), raw: '1500AA1122' })),
      (code) => code === 'SEA'
    );
    assert.strictEqual(mismatchOnPackets.valid, false);
    assert.match(mismatchOnPackets.error!, /origin_id in payload must match/);
  });

  it('bounds stored unapprovedIata length in ObserverRegionBlocklist.block()', () => {
    const blocklist = new ObserverRegionBlocklist(60_000, 100, 0);
    try {
      blocklist.block(validPubKey, 'a'.repeat(60000));
      const stats = blocklist.getStats();
      assert.strictEqual(stats.blockedObservers.length, 1);
      assert.strictEqual(stats.blockedObservers[0].unapprovedIata, 'A'.repeat(16));
      assert.ok(stats.blockedObservers[0].unapprovedIata.length <= 16);
    } finally {
      blocklist.destroy();
    }
  });

  it('clamps MQTT_LWT_GRACE_MS to MAX_LWT_GRACE_MS (30s) in loadMqttConfig()', () => {
    const prevWs = process.env.MQTT_WS_PORT;
    const prevHost = process.env.MQTT_HOST;
    const prevAud = process.env.AUTH_EXPECTED_AUDIENCE;
    const prevGrace = process.env.MQTT_LWT_GRACE_MS;
    try {
      process.env.MQTT_WS_PORT = '8883';
      process.env.MQTT_HOST = '127.0.0.1';
      process.env.AUTH_EXPECTED_AUDIENCE = 'audit.meshcore.local';
      process.env.MQTT_LWT_GRACE_MS = '999999';
      const cfg = loadMqttConfig();
      assert.strictEqual(cfg.lwtGraceMs, MAX_LWT_GRACE_MS);
      assert.strictEqual(cfg.lwtGraceMs, 30_000);
    } finally {
      if (prevWs === undefined) delete process.env.MQTT_WS_PORT; else process.env.MQTT_WS_PORT = prevWs;
      if (prevHost === undefined) delete process.env.MQTT_HOST; else process.env.MQTT_HOST = prevHost;
      if (prevAud === undefined) delete process.env.AUTH_EXPECTED_AUDIENCE; else process.env.AUTH_EXPECTED_AUDIENCE = prevAud;
      if (prevGrace === undefined) delete process.env.MQTT_LWT_GRACE_MS; else process.env.MQTT_LWT_GRACE_MS = prevGrace;
    }
  });
});

describe('Observer Compatibility: End-to-End Broker Verification', () => {
  it('accepts OffbandMesh slim /packets (omitted origin_id), populates origin_id, and keeps session open for /raw', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-slim-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let brokerProc: ChildProcess | undefined;

    try {
      const broker = await spawnBroker('slim-packets', port, audience, tempDir);
      brokerProc = broker.proc;
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('meshcore/#');

      const jwt = await createPeerJwt(obsKey, audience, 3600);
      const obs = await connectMqttWsClient(wsUrl, 'offband_obs', `v1_${obsKey.publicKeyHex}`, jwt);
      clients.push(obs);

      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/packets`,
        JSON.stringify({ type: 'PACKET', direction: 'rx', raw: '1500DEADBEEF' })
      );
      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/raw`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, payload: '1500DEADBEEF' })
      );

      const pktMsg = await sub.waitForMessage((m) => m.topic.endsWith('/packets'));
      const rawMsg = await sub.waitForMessage((m) => m.topic.endsWith('/raw'));

      assert.strictEqual(obs.ws.readyState, WebSocket.OPEN);
      const parsedPkt = JSON.parse(pktMsg.payload);
      assert.strictEqual(parsedPkt.origin_id, obsKey.publicKeyHex);
      assert.strictEqual(parsedPkt.raw, '1500DEADBEEF');
      assert.ok(rawMsg.payload.includes('1500DEADBEEF'));
    } finally {
      for (const c of clients) c.close();
      brokerProc?.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('delivers unclean CONNECT-time LWT offline after newer online status (including slow-clock reconnect)', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-lwt-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let brokerProc: ChildProcess | undefined;

    try {
      const broker = await spawnBroker('unclean-lwt', port, audience, tempDir, {
        MQTT_LWT_GRACE_MS: '250',
      });
      brokerProc = broker.proc;
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('meshcore/#');

      const t0Slow = Date.now() - 120_000;
      const onlineTs = new Date(t0Slow + 500).toISOString();
      const jwt = await createPeerJwt(obsKey, audience, 3600);
      const obs1 = await connectMqttWsClient(wsUrl, 'slow_obs', `v1_${obsKey.publicKeyHex}`, jwt, {
        topic: `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        payload: Buffer.from(
          JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'offline', timestamp: new Date(t0Slow).toISOString() }),
          'utf-8'
        ),
        qos: 0,
        retain: true,
      });

      await obs1.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: onlineTs }),
        true
      );
      await sub.waitForMessage((m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'online');

      const closed = obs1.waitForClose(3000);
      obs1.ws.terminate();
      await closed;

      const offlineMsg = await sub.waitForMessage(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'offline',
        2000
      );
      const parsedOffline = JSON.parse(offlineMsg.payload);
      assert.strictEqual(offlineMsg.retain, false);
      assert.ok(Date.parse(parsedOffline.timestamp) >= Date.parse(onlineTs));

      // Observer reconnects immediately with its slow clock advancing past t0Slow + 500ms
      const reconnectOnlineTs = new Date(t0Slow + 1000).toISOString();
      const obs2 = await connectMqttWsClient(wsUrl, 'slow_obs', `v1_${obsKey.publicKeyHex}`, jwt);
      clients.push(obs2);
      await obs2.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: reconnectOnlineTs })
      );

      const reconnectOnlineMsg = await sub.waitForMessage(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).timestamp === reconnectOnlineTs,
        2000
      );
      assert.strictEqual(JSON.parse(reconnectOnlineMsg.payload).status, 'online');
    } finally {
      for (const c of clients) c.close();
      brokerProc?.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('suppresses LWT on same-key takeover and rapid reconnect, while ignoring unauthenticated hijacks', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-takeover-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const attackerKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let brokerProc: ChildProcess | undefined;

    try {
      const broker = await spawnBroker('lwt-suppress', port, audience, tempDir, {
        MQTT_LWT_GRACE_MS: '400',
      });
      brokerProc = broker.proc;
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('meshcore/#');

      const validJwt = await createPeerJwt(obsKey, audience, 3600);
      const clientId = 'renew_id';

      // 1. Overlapping same-clientId takeover (agessaman reconnect())
      const c1 = await connectMqttWsClient(wsUrl, clientId, `v1_${obsKey.publicKeyHex}`, validJwt, {
        topic: `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        payload: Buffer.from(
          JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'offline', timestamp: new Date().toISOString() }),
          'utf-8'
        ),
        qos: 0,
        retain: false,
      });
      await c1.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: new Date().toISOString() })
      );
      await sub.waitForMessage((m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'online');

      // Bad JWT hijack attempt using same clientId must fail without touching c1
      const badJwt = await createPeerJwt(attackerKey, audience, 3600);
      await assert.rejects(
        () => connectMqttWsClient(wsUrl, clientId, `v1_${obsKey.publicKeyHex}`, badJwt),
        /CONNACK refused with code 5/
      );
      assert.strictEqual(c1.ws.readyState, WebSocket.OPEN);

      // Legitimate replacement session takes over same clientId
      const c1Closed = c1.waitForClose(3000);
      const c2 = await connectMqttWsClient(wsUrl, clientId, `v1_${obsKey.publicKeyHex}`, validJwt, {
        topic: `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        payload: Buffer.from(
          JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'offline', timestamp: new Date().toISOString() }),
          'utf-8'
        ),
        qos: 0,
        retain: false,
      });
      clients.push(c2);
      await c1Closed;
      await new Promise((r) => setTimeout(r, 500));

      assert.strictEqual(
        sub.received.some((m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'offline'),
        false,
        'Overlapping same-key takeover must suppress offline LWT'
      );

      // Verify c2 retained its own LWT after displacing c1
      await c2.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: new Date().toISOString() })
      );
      const c2Closed = c2.waitForClose(3000);
      c2.ws.terminate();
      await c2Closed;

      await sub.waitForMessage(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'offline',
        2000
      );
      const offlineAfterC2 = sub.received.filter(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'offline'
      ).length;
      assert.strictEqual(offlineAfterC2, 1, 'Replacement session c2 must keep its own LWT after takeover');

      // 2. Non-overlapping rapid reconnect within MQTT_LWT_GRACE_MS=400ms
      const c3 = await connectMqttWsClient(wsUrl, 'renew_id_2', `v1_${obsKey.publicKeyHex}`, validJwt, {
        topic: `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        payload: Buffer.from(
          JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'offline', timestamp: new Date().toISOString() }),
          'utf-8'
        ),
        qos: 0,
        retain: false,
      });
      clients.push(c3);
      await c3.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: new Date().toISOString() })
      );
      const c3Closed = c3.waitForClose(3000);
      c3.ws.terminate();
      await c3Closed;
      await new Promise((r) => setTimeout(r, 50));

      const c4 = await connectMqttWsClient(wsUrl, 'renew_id_3', `v1_${obsKey.publicKeyHex}`, validJwt);
      clients.push(c4);
      await new Promise((r) => setTimeout(r, 600));

      const offlineAfterC3 = sub.received.filter(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'offline'
      ).length;
      assert.strictEqual(
        offlineAfterC3,
        1,
        'Rapid reconnect within grace window must cancel deferred offline LWT'
      );
    } finally {
      for (const c of clients) c.close();
      brokerProc?.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('suppresses wills and rate-blocks XYZ/XXX loops without ALLOWED_REGIONS, and enforces IATA on serial/commands', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-iata-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const xyzKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const xxxKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let broker: { proc: ChildProcess; logs: () => string } | undefined;

    try {
      broker = await spawnBroker('iata-suppress', port, audience, tempDir);
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('meshcore/#');

      // 1. XYZ status with XYZ LWT and ALLOWED_REGIONS unset
      const xyzJwt = await createPeerJwt(xyzKey, audience, 3600);
      const xyzClient = await connectMqttWsClient(wsUrl, 'ha_xyz', `v1_${xyzKey.publicKeyHex}`, xyzJwt, {
        topic: `meshcore/XYZ/${xyzKey.publicKeyHex}/status`,
        payload: Buffer.from(
          JSON.stringify({ origin_id: xyzKey.publicKeyHex, status: 'offline', timestamp: new Date().toISOString() }),
          'utf-8'
        ),
        qos: 0,
        retain: false,
      });
      clients.push(xyzClient);
      const xyzClosed = xyzClient.waitForClose(3000);
      await xyzClient.publish(
        `meshcore/XYZ/${xyzKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: xyzKey.publicKeyHex, status: 'online', timestamp: new Date().toISOString() })
      );
      await xyzClosed;

      // Subsequent reconnect must be rejected immediately by observerRegionBlocklist
      await assert.rejects(
        () => connectMqttWsClient(wsUrl, 'ha_xyz_retry', `v1_${xyzKey.publicKeyHex}`, xyzJwt),
        /CONNACK refused with code 5/
      );

      // 2. XXX on serial/commands subscribe must deny, suppress will, and close
      const xxxJwt = await createPeerJwt(xxxKey, audience, 3600);
      const xxxClient = await connectMqttWsClient(wsUrl, 'cis_xxx', `v1_${xxxKey.publicKeyHex}`, xxxJwt, {
        topic: `meshcore/XXX/${xxxKey.publicKeyHex}/status`,
        payload: Buffer.from(
          JSON.stringify({ origin_id: xxxKey.publicKeyHex, status: 'offline', timestamp: new Date().toISOString() }),
          'utf-8'
        ),
        qos: 0,
        retain: false,
      });
      clients.push(xxxClient);
      const xxxClosed = xxxClient.waitForClose(3000);
      await xxxClient.subscribe(`meshcore/XXX/${xxxKey.publicKeyHex}/serial/commands`).catch(() => {});
      await xxxClosed;
      await new Promise((r) => setTimeout(r, 200));

      assert.strictEqual(
        sub.received.some((m) => m.topic.includes(xyzKey.publicKeyHex) || m.topic.includes(xxxKey.publicKeyHex)),
        false
      );

      const xyzDenials = broker.logs().match(/Publish denied -> .*\/XYZ\/.*\(invalid IATA\)/g) || [];
      assert.strictEqual(xyzDenials.length, 1, 'Expected single invalid IATA publish denial without duplicate LWT denial');
    } finally {
      for (const c of clients) c.close();
      broker?.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('strips retain flag on /neighbors, clarifies expired JWT logs, normalizes zoneless localtime_r, and sends single WebSocket PONG', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-p1p2-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let broker: { proc: ChildProcess; logs: () => string } | undefined;

    try {
      broker = await spawnBroker('p1p2-compat', port, audience, tempDir, {
        MQTT_LWT_GRACE_MS: '0',
      });
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub1 = await connectMqttWsClient(wsUrl, 'sub_admin_1', 'admin', 'adminpass123');
      clients.push(sub1);
      await sub1.subscribe('meshcore/#');

      // Single WebSocket PONG per PING
      sub1.ws.ping(Buffer.from('hb'));
      await new Promise((r) => setTimeout(r, 150));
      assert.strictEqual(sub1.getPongCount(), 1, 'Broker must send exactly one WebSocket PONG per PING');

      // Expired JWT must log "Expired auth token" instead of "Invalid token signature"
      const expiredJwt = await createPeerJwt(obsKey, audience, -60);
      await assert.rejects(
        () => connectMqttWsClient(wsUrl, 'expired_obs', `v1_${obsKey.publicKeyHex}`, expiredJwt),
        /CONNACK refused with code 5/
      );
      assert.match(broker.logs(), /Expired auth token/);
      assert.doesNotMatch(broker.logs(), /Invalid token signature/);

      const jwt = await createPeerJwt(obsKey, audience, 3600);
      const obs = await connectMqttWsClient(wsUrl, 'compat_obs', `v1_${obsKey.publicKeyHex}`, jwt);
      clients.push(obs);

      // Retain flag stripped on /neighbors
      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/neighbors`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, neighbors: [] }),
        true
      );
      const liveNbr = await sub1.waitForMessage((m) => m.topic.endsWith('/neighbors'));
      assert.strictEqual(liveNbr.retain, false);

      const sub2 = await connectMqttWsClient(wsUrl, 'sub_admin_2', 'admin', 'adminpass123');
      clients.push(sub2);
      await sub2.subscribe('meshcore/#');
      await new Promise((r) => setTimeout(r, 150));
      assert.strictEqual(
        sub2.received.some((m) => m.topic.endsWith('/neighbors')),
        false,
        'Late subscriber must not receive retained /neighbors'
      );

      // Zoneless localtime_r timestamps (UTC+9 then UTC-8, followed by standard UTC online & offline)
      const nowMs = Date.now();
      const toZoneless = (ms: number) => `${new Date(ms).toISOString().replace('Z', '')}000`;
      const utcPlus9 = toZoneless(nowMs + 9 * 3600 * 1000);
      const utcMinus8 = toZoneless(nowMs - 8 * 3600 * 1000 + 10);
      const standardUtcOnline = new Date(nowMs + 50).toISOString();
      const standardUtcOffline = new Date(nowMs + 100).toISOString();

      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: utcPlus9 })
      );
      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: utcMinus8 })
      );
      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: standardUtcOnline })
      );
      await obs.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/status`,
        JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'offline', timestamp: standardUtcOffline })
      );

      const deliveredOnline = await sub1.waitForMessage(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).timestamp === standardUtcOnline
      );
      const deliveredOffline = await sub1.waitForMessage(
        (m) => m.topic.endsWith('/status') && JSON.parse(m.payload).timestamp === standardUtcOffline
      );
      assert.strictEqual(JSON.parse(deliveredOnline.payload).status, 'online');
      assert.strictEqual(JSON.parse(deliveredOffline.payload).status, 'offline');
    } finally {
      for (const c of clients) c.close();
      broker?.proc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('prevents blocklist memory exhaustion on oversized or invalid-format topics on publish and subscribe', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-blockcap-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const k1 = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const k2 = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const k3 = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let brokerProc: ChildProcess | undefined;

    try {
      const broker = await spawnBroker('blockcap', port, audience, tempDir, {
        MQTT_SYS_INTERVAL_MS: '250',
      });
      brokerProc = broker.proc;
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('$SYS/broker/security/region_filter');

      // 1. Oversized publish topic (60KB segment -> blocked as INVALID via MAX_TOPIC_LENGTH)
      const c1 = await connectMqttWsClient(
        wsUrl,
        'huge_pub',
        `v1_${k1.publicKeyHex}`,
        await createPeerJwt(k1, audience, 3600)
      );
      clients.push(c1);
      const c1Closed = c1.waitForClose(3000);
      await c1.publish(
        `meshcore/${'A'.repeat(60000)}/${k1.publicKeyHex}/status`,
        JSON.stringify({ origin_id: k1.publicKeyHex, status: 'online' })
      );
      await c1Closed;

      // 2. Oversized subscribe topic (60KB segment -> blocked as INVALID via MAX_TOPIC_LENGTH)
      const c2 = await connectMqttWsClient(
        wsUrl,
        'huge_sub',
        `v1_${k2.publicKeyHex}`,
        await createPeerJwt(k2, audience, 3600)
      );
      clients.push(c2);
      const c2Closed = c2.waitForClose(3000);
      await c2.subscribe(`meshcore/${'B'.repeat(60000)}/${k2.publicKeyHex}/serial/commands`).catch(() => {});
      await c2Closed;

      // 3. Under-256B invalid format location code (blocked as INVALID without storing raw segment)
      const c3 = await connectMqttWsClient(
        wsUrl,
        'bad_fmt_pub',
        `v1_${k3.publicKeyHex}`,
        await createPeerJwt(k3, audience, 3600)
      );
      clients.push(c3);
      const c3Closed = c3.waitForClose(3000);
      await c3.publish(
        `meshcore/INVALID_LONG_REGION_CODE_12345/${k3.publicKeyHex}/status`,
        JSON.stringify({ origin_id: k3.publicKeyHex, status: 'online' })
      );
      await c3Closed;

      const sysMsg = await sub.waitForMessage((m) => {
        if (m.topic !== '$SYS/broker/security/region_filter') return false;
        const data = JSON.parse(m.payload);
        return (data.observerBlocklist?.blockedObservers?.length || 0) >= 3;
      }, 3000);

      const blockedObservers = JSON.parse(sysMsg.payload).observerBlocklist.blockedObservers;
      assert.strictEqual(blockedObservers.length, 3);
      for (const rec of blockedObservers) {
        assert.strictEqual(rec.unapprovedIata, 'INVALID');
        assert.ok(rec.unapprovedIata.length <= 16);
      }
    } finally {
      for (const c of clients) c.close();
      brokerProc?.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('drops stale LWT when a newer status arrives from a peered broker (grace > 0 and grace = 0)', async () => {
    for (const graceMs of ['250', '0']) {
      const tempDir = mkdtempSync(join(tmpdir(), `meshcore-compat-peer-lwt-${graceMs}-`));
      const port = await getFreePort();
      const audience = 'compat.meshcore.local';
      const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
      const peerKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
      const clients: MqttWsClient[] = [];
      let brokerProc: ChildProcess | undefined;

      try {
        const broker = await spawnBroker(`peer-lwt-${graceMs}`, port, audience, tempDir, {
          AUTHORIZED_PEERS: peerKey.publicKeyHex,
          MQTT_LWT_GRACE_MS: graceMs,
        });
        brokerProc = broker.proc;
        const wsUrl = `ws://127.0.0.1:${port}`;

        const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
        clients.push(sub);
        await sub.subscribe('meshcore/#');

        const nowMs = Date.now();
        const t0Iso = new Date(nowMs - 5000).toISOString();
        const t1Iso = new Date(nowMs - 2000).toISOString();
        const t2Iso = new Date(nowMs).toISOString();

        const obsJwt = await createPeerJwt(obsKey, audience, 3600);
        const obsClient = await connectMqttWsClient(wsUrl, 'obs_a', `v1_${obsKey.publicKeyHex}`, obsJwt, {
          topic: `meshcore/SEA/${obsKey.publicKeyHex}/status`,
          payload: Buffer.from(
            JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'offline', timestamp: t0Iso }),
            'utf-8'
          ),
          qos: 0,
          retain: false,
        });
        clients.push(obsClient);

        await obsClient.publish(
          `meshcore/SEA/${obsKey.publicKeyHex}/status`,
          JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: t1Iso })
        );
        await sub.waitForMessage((m) => m.topic.endsWith('/status') && JSON.parse(m.payload).timestamp === t1Iso);

        // Simulated failover: Broker B forwards newer "online" status via Peer link
        const peerJwt = await createPeerJwt(peerKey, audience, 3600);
        const peerClient = await connectMqttWsClient(wsUrl, 'peer_b', `v1_${peerKey.publicKeyHex}`, peerJwt);
        clients.push(peerClient);
        await peerClient.publish(
          `meshcore/SEA/${obsKey.publicKeyHex}/status`,
          JSON.stringify({ origin_id: obsKey.publicKeyHex, status: 'online', timestamp: t2Iso })
        );
        await sub.waitForMessage((m) => m.topic.endsWith('/status') && JSON.parse(m.payload).timestamp === t2Iso);

        // Dying connection on Broker A terminates abruptly
        const obsClosed = obsClient.waitForClose(3000);
        obsClient.ws.terminate();
        await obsClosed;

        await new Promise((r) => setTimeout(r, parseInt(graceMs, 10) + 300));
        assert.strictEqual(
          sub.received.some((m) => m.topic.endsWith('/status') && JSON.parse(m.payload).status === 'offline'),
          false,
          `Stale LWT with MQTT_LWT_GRACE_MS=${graceMs} must not overwrite newer peered online status`
        );
      } finally {
        for (const c of clients) c.close();
        brokerProc?.kill('SIGTERM');
        await new Promise((r) => setTimeout(r, 150));
        rmSync(tempDir, { recursive: true, force: true });
      }
    }
  });

  it('enriches inbound peer slim /packets missing origin_id', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-compat-peer-slim-'));
    const port = await getFreePort();
    const audience = 'compat.meshcore.local';
    const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const peerKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const clients: MqttWsClient[] = [];
    let brokerProc: ChildProcess | undefined;

    try {
      const broker = await spawnBroker('peer-slim', port, audience, tempDir, {
        AUTHORIZED_PEERS: peerKey.publicKeyHex,
      });
      brokerProc = broker.proc;
      const wsUrl = `ws://127.0.0.1:${port}`;

      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('meshcore/#');

      const peerJwt = await createPeerJwt(peerKey, audience, 3600);
      const peerClient = await connectMqttWsClient(wsUrl, 'peer_in', `v1_${peerKey.publicKeyHex}`, peerJwt);
      clients.push(peerClient);

      await peerClient.publish(
        `meshcore/SEA/${obsKey.publicKeyHex}/packets`,
        JSON.stringify({ type: 'PACKET', direction: 'rx', raw: '1500CAFEBABE' })
      );

      const pktMsg = await sub.waitForMessage((m) => m.topic.endsWith('/packets'));
      const parsed = JSON.parse(pktMsg.payload);
      assert.strictEqual(parsed.origin_id, obsKey.publicKeyHex);
      assert.strictEqual(parsed.raw, '1500CAFEBABE');
    } finally {
      for (const c of clients) c.close();
      brokerProc?.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
