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
import {
  parseAllowedRegions,
  isRegionAllowed,
  ObserverRegionBlocklist,
} from '../src/region-filter.js';

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

interface MqttWsClient {
  ws: WebSocket;
  received: Array<{ topic: string; payload: string }>;
  publish: (topic: string, payload: string) => Promise<void>;
  subscribe: (topic: string) => Promise<void>;
  waitForClose: (timeoutMs?: number) => Promise<void>;
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
    const received: Array<{ topic: string; payload: string }> = [];
    let subWaiter: (() => void) | null = null;
    let connected = false;
    let isClosed = false;
    const closeListeners: Array<() => void> = [];

    const timeout = setTimeout(() => {
      ws.terminate();
      reject(new Error(`Timed out connecting MQTT WS client ${clientId} to ${url}`));
    }, 8000);

    ws.on('close', () => {
      isClosed = true;
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
          publish: (topic: string, payload: string) =>
            new Promise<void>((res, rej) => {
              const buf = mqttPacket.generate({
                cmd: 'publish',
                topic,
                payload: Buffer.from(payload, 'utf-8'),
                qos: 0,
                retain: false,
                dup: false,
              });
              ws.send(buf, (err) => (err ? rej(err) : res()));
            }),
          subscribe: (topic: string) =>
            new Promise<void>((res, rej) => {
              subWaiter = res;
              const buf = mqttPacket.generate({
                cmd: 'subscribe',
                messageId: 1,
                subscriptions: [{ topic, qos: 0 }],
              });
              ws.send(buf, (err) => {
                if (err) {
                  subWaiter = null;
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
              const timer = setTimeout(() => rej(new Error(`Timed out waiting for ${clientId} to close`)), timeoutMs);
              closeListeners.push(() => {
                clearTimeout(timer);
                res();
              });
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
          cb();
        }
      } else if (packet.cmd === 'publish') {
        received.push({
          topic: packet.topic,
          payload: packet.payload.toString('utf-8'),
        });
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
  extraEnv: Record<string, string>
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
    MQTT_SYS_INTERVAL_MS: '300',
    SUBSCRIBER_MAX_CONNECTIONS_DEFAULT: '5',
    SUBSCRIBER_1: 'admin:adminpass123:1:5',
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

describe('Region Filtering: Configuration & Unit Tests', () => {
  it('returns null (bypass mode) when ALLOWED_REGIONS is undefined, empty, or whitespace', () => {
    assert.strictEqual(parseAllowedRegions(undefined), null);
    assert.strictEqual(parseAllowedRegions(''), null);
    assert.strictEqual(parseAllowedRegions('   '), null);
    assert.strictEqual(parseAllowedRegions(' , , '), null);

    // When allowedRegions is null, all regions are permitted unconditionally
    assert.strictEqual(isRegionAllowed('DFW', null), true);
    assert.strictEqual(isRegionAllowed('SEA', null), true);
    assert.strictEqual(isRegionAllowed('test', null), true);
  });

  it('parses ALLOWED_REGIONS into a sanitized, trimmed, case-insensitive set', () => {
    const allowed = parseAllowedRegions(' dfw , ORD,lax ');
    assert.ok(allowed);
    assert.strictEqual(allowed.size, 3);
    assert.strictEqual(allowed.has('DFW'), true);
    assert.strictEqual(allowed.has('ORD'), true);
    assert.strictEqual(allowed.has('LAX'), true);

    assert.strictEqual(isRegionAllowed('DFW', allowed), true);
    assert.strictEqual(isRegionAllowed('dfw', allowed), true);
    assert.strictEqual(isRegionAllowed(' ord ', allowed), true);
    assert.strictEqual(isRegionAllowed('SEA', allowed), false);
    assert.strictEqual(isRegionAllowed('test', allowed), false);
  });

  it('only permits "test" when explicitly listed in ALLOWED_REGIONS and ignores XXX/invalid tokens', () => {
    const allowedWithTest = parseAllowedRegions('DFW, TeSt , XXX, INVALID123');
    assert.ok(allowedWithTest);
    assert.strictEqual(allowedWithTest.size, 2);
    assert.strictEqual(isRegionAllowed('DFW', allowedWithTest), true);
    assert.strictEqual(isRegionAllowed('test', allowedWithTest), true);
    assert.strictEqual(isRegionAllowed('TEST', allowedWithTest), true);
    assert.strictEqual(isRegionAllowed('XXX', allowedWithTest), false);
  });
});

describe('ObserverRegionBlocklist: 1-Minute Cooldown & Expiration', () => {
  it('blocks observer public keys for 1 minute (60s) by default and expires cleanly', async () => {
    const defaultList = new ObserverRegionBlocklist(undefined, 100, 0);
    try {
      const stats = defaultList.getStats();
      assert.strictEqual(stats.blockDurationSeconds, 60);
    } finally {
      defaultList.destroy();
    }

    // Short 80ms duration for fast expiration verification
    const blocklist = new ObserverRegionBlocklist(80, 5, 0);
    try {
      const pubKey = 'a'.repeat(64);
      assert.strictEqual(blocklist.isBlocked(pubKey), false);

      blocklist.block(pubKey, 'SEA');
      const check1 = blocklist.checkBlock(pubKey.toUpperCase());
      assert.strictEqual(check1.blocked, true);
      assert.strictEqual(check1.unapprovedIata, 'SEA');
      assert.ok(check1.remainingSeconds >= 1);

      const check2 = blocklist.checkBlock(pubKey.toLowerCase());
      assert.strictEqual(check2.blocked, true);

      const statsWhileBlocked = blocklist.getStats();
      assert.strictEqual(statsWhileBlocked.blockedObserverCount, 1);
      assert.strictEqual(statsWhileBlocked.totalBlocksIssued, 1);
      assert.strictEqual(statsWhileBlocked.totalBlockedReconnects, 2);
      assert.strictEqual(statsWhileBlocked.blockedObservers[0].rejectedReconnects, 2);

      // Wait for block timer to expire
      await new Promise((r) => setTimeout(r, 100));
      assert.strictEqual(blocklist.isBlocked(pubKey), false);
      assert.strictEqual(blocklist.getStats().blockedObserverCount, 0);
    } finally {
      blocklist.destroy();
    }
  });
});

describe('End-to-End Broker Enforcement: ALLOWED_REGIONS (Peers vs. Observers)', () => {
  it('selectively drops unapproved Peer packets while keeping Peer connected, and disconnects + 1m-blocks unapproved Observers', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-region-filter-'));
    const port = await getFreePort();
    const audience = 'broker-region.meshcore.local';

    const peerKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const peerOriginKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const badObserverKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const goodObserverKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));

    const brokers: ChildProcess[] = [];
    const clients: MqttWsClient[] = [];

    try {
      const broker = await spawnBroker('region-broker', port, audience, tempDir, {
        ALLOWED_REGIONS: 'dfw, ORD, lax',
        AUTHORIZED_PEERS: peerKey.publicKeyHex,
      });
      brokers.push(broker.proc);

      const wsUrl = `ws://127.0.0.1:${port}`;

      // 1. Connect Admin Subscriber to observe all meshcore/# and $SYS/# traffic
      const sub = await connectMqttWsClient(wsUrl, 'sub_admin', 'admin', 'adminpass123');
      clients.push(sub);
      await sub.subscribe('meshcore/#');
      await sub.subscribe('$SYS/broker/#');

      // 2. Connect Inbound Peer (ClientType.PEER via Ed25519 JWT)
      const peerJwt = await createPeerJwt(peerKey, audience, 3600);
      const peerClient = await connectMqttWsClient(
        wsUrl,
        `peer_in_${peerKey.publicKeyHex.substring(0, 8)}`,
        `v1_${peerKey.publicKeyHex}`,
        peerJwt
      );
      clients.push(peerClient);

      // Peer publishes unapproved IATA (SEA) -> must be dropped silently AND Peer stays connected
      const seaPeerPayload = JSON.stringify({
        origin_id: peerOriginKey.publicKeyHex,
        data: 'unapproved_sea_from_peer',
      });
      await peerClient.publish(`meshcore/SEA/${peerOriginKey.publicKeyHex}/packets`, seaPeerPayload);

      // Peer immediately publishes approved IATAs (DFW and ORD) on the SAME connection -> must succeed
      const dfwPeerPayload = JSON.stringify({
        origin_id: peerOriginKey.publicKeyHex,
        data: 'approved_dfw_from_peer',
      });
      const ordPeerPayload = JSON.stringify({
        origin_id: peerOriginKey.publicKeyHex,
        status: 'online',
        timestamp: new Date().toISOString(),
      });
      await peerClient.publish(`meshcore/DFW/${peerOriginKey.publicKeyHex}/packets`, dfwPeerPayload);
      await peerClient.publish(`meshcore/ORD/${peerOriginKey.publicKeyHex}/status`, ordPeerPayload);

      await new Promise((r) => setTimeout(r, 150));

      assert.strictEqual(
        peerClient.ws.readyState,
        WebSocket.OPEN,
        'Peer connection must remain open after publishing unapproved IATA'
      );
      assert.strictEqual(
        sub.received.some((m) => m.topic.startsWith('meshcore/SEA/')),
        false,
        'Unapproved SEA packet from Peer must be dropped'
      );
      assert.strictEqual(
        sub.received.some((m) => m.topic === `meshcore/DFW/${peerOriginKey.publicKeyHex}/packets`),
        true,
        'Subsequent approved DFW packet on same Peer connection must be delivered'
      );
      assert.strictEqual(
        sub.received.some((m) => m.topic === `meshcore/ORD/${peerOriginKey.publicKeyHex}/status`),
        true,
        'Subsequent approved ORD status on same Peer connection must be delivered'
      );

      // 3. Connect Observer 1 (ClientType.PUBLISHER) with an LWT on unapproved SEA, then publish to SEA
      const badObsJwt = await createPeerJwt(badObserverKey, audience, 3600);
      const badObsClient = await connectMqttWsClient(
        wsUrl,
        `obs_bad_${badObserverKey.publicKeyHex.substring(0, 8)}`,
        `v1_${badObserverKey.publicKeyHex}`,
        badObsJwt,
        {
          topic: `meshcore/SEA/${badObserverKey.publicKeyHex}/status`,
          payload: Buffer.from(
            JSON.stringify({
              origin_id: badObserverKey.publicKeyHex,
              status: 'offline',
              timestamp: new Date().toISOString(),
            }),
            'utf-8'
          ),
          qos: 0,
          retain: false,
        }
      );
      clients.push(badObsClient);

      const badObsClosePromise = badObsClient.waitForClose(3000);
      await badObsClient.publish(
        `meshcore/SEA/${badObserverKey.publicKeyHex}/packets`,
        JSON.stringify({
          origin_id: badObserverKey.publicKeyHex,
          data: 'unapproved_sea_from_observer',
        })
      );

      // Observer session must be terminated immediately
      await badObsClosePromise;
      await new Promise((r) => setTimeout(r, 100));

      assert.strictEqual(
        sub.received.some((m) => m.topic.includes(badObserverKey.publicKeyHex)),
        false,
        'Both the unapproved packet and LWT from the terminated Observer must be dropped'
      );

      // 4. Reconnection attempts by the blocked Observer (>10 times to verify IP RateLimiter is NOT triggered)
      for (let attempt = 1; attempt <= 11; attempt++) {
        await assert.rejects(
          () =>
            connectMqttWsClient(
              wsUrl,
              `obs_bad_retry_${attempt}`,
              `v1_${badObserverKey.publicKeyHex}`,
              badObsJwt
            ),
          /CONNACK refused with code 5/,
          `Reconnect attempt ${attempt} by blocked observer must be rejected`
        );
      }

      // 5. Verify a different Observer on the same IP (127.0.0.1) can still connect and publish to approved DFW
      const goodObsJwt = await createPeerJwt(goodObserverKey, audience, 3600);
      const goodObsClient = await connectMqttWsClient(
        wsUrl,
        `obs_good_${goodObserverKey.publicKeyHex.substring(0, 8)}`,
        `v1_${goodObserverKey.publicKeyHex}`,
        goodObsJwt
      );
      clients.push(goodObsClient);

      await goodObsClient.publish(
        `meshcore/DFW/${goodObserverKey.publicKeyHex}/packets`,
        JSON.stringify({
          origin_id: goodObserverKey.publicKeyHex,
          data: 'approved_dfw_from_good_observer',
        })
      );

      // Wait for $SYS snapshot tick (300ms interval)
      await new Promise((r) => setTimeout(r, 450));

      assert.strictEqual(
        sub.received.some((m) => m.topic === `meshcore/DFW/${goodObserverKey.publicKeyHex}/packets`),
        true,
        'Approved DFW packet from good observer on same IP must succeed'
      );

      // Verify $SYS/broker/regions/allowed and $SYS/broker/security/region_filter
      const allowedTopicMsg = sub.received.filter((m) => m.topic === '$SYS/broker/regions/allowed').pop();
      assert.ok(allowedTopicMsg, 'Expected $SYS/broker/regions/allowed to be published');
      assert.strictEqual(allowedTopicMsg.payload, 'DFW,LAX,ORD');

      const regionFilterMsg = sub.received.filter((m) => m.topic === '$SYS/broker/security/region_filter').pop();
      assert.ok(regionFilterMsg, 'Expected $SYS/broker/security/region_filter to be published');
      const regionFilterData = JSON.parse(regionFilterMsg.payload);
      assert.strictEqual(regionFilterData.enabled, true);
      assert.strictEqual(regionFilterData.peerPacketsDropped, 1);
      assert.strictEqual(regionFilterData.observerBlocklist.blockedObserverCount, 1);
      assert.strictEqual(
        regionFilterData.observerBlocklist.blockedObservers[0].publicKey,
        badObserverKey.publicKeyHex
      );
      assert.strictEqual(regionFilterData.observerBlocklist.blockedObservers[0].unapprovedIata, 'SEA');
      assert.strictEqual(regionFilterData.observerBlocklist.blockedObservers[0].rejectedReconnects, 11);
    } finally {
      for (const c of clients) c.close();
      for (const p of brokers) p.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 150));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
