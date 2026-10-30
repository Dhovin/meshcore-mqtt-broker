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
  close: () => void;
}

async function connectMqttWsClient(
  url: string,
  clientId: string,
  username: string,
  password: string
): Promise<MqttWsClient> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, ['mqtt']);
    const parser = mqttPacket.parser({ protocolVersion: 4 });
    const received: Array<{ topic: string; payload: string }> = [];
    let subWaiter: (() => void) | null = null;
    let connected = false;

    const timeout = setTimeout(() => {
      ws.terminate();
      reject(new Error(`Timed out connecting MQTT WS client ${clientId} to ${url}`));
    }, 8000);

    parser.on('packet', (packet: any) => {
      if (packet.cmd === 'connack') {
        clearTimeout(timeout);
        if (packet.returnCode !== 0) {
          ws.close();
          reject(new Error(`CONNACK refused with code ${packet.returnCode} for ${clientId}`));
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
      const connectBuf = mqttPacket.generate({
        cmd: 'connect',
        protocolId: 'MQTT',
        protocolVersion: 4,
        clean: true,
        keepalive: 30,
        clientId,
        username,
        password: Buffer.from(password, 'utf-8'),
      });
      ws.send(connectBuf);
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

  const proc = spawn(process.execPath, ['dist/server.js'], {
    env: {
      ...process.env,
      LOG_LEVEL: 'info',
      MQTT_WS_PORT: String(wsPort),
      MQTT_TCP_PORT: String(wsPort + 1000),
      ENABLE_TCP_MQTT: 'false',
      MQTT_HOST: '127.0.0.1',
      AUTH_EXPECTED_AUDIENCE: audience,
      HTTP_REDIRECT_URL: '',
      MQTT_MAX_PACKET_BYTES: '65536',
      MQTT_SYS_INTERVAL_MS: '500',
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
      ...extraEnv,
    },
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

describe('Multi-Peer Topology: Broker A -> B & C, and Broker C -> B (Origin-Only Forwarding)', () => {
  it('forwards local observer packets to peers, never re-forwards peer packets (no C->B duplicate), and deduplicates dual-connected observers', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-multi-peer-'));
    const portA = await getFreePort();
    const portB = await getFreePort();
    const portC = await getFreePort();

    const seedA = crypto.randomBytes(32).toString('hex');
    const seedB = crypto.randomBytes(32).toString('hex');
    const seedC = crypto.randomBytes(32).toString('hex');

    const peerKeyA = await derivePeerKeyPair(seedA);
    const peerKeyB = await derivePeerKeyPair(seedB);
    const peerKeyC = await derivePeerKeyPair(seedC);

    const obs1Key = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));
    const obs2Key = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));

    const brokers: ChildProcess[] = [];
    const clients: MqttWsClient[] = [];

    try {
      // Start Broker B (receives from Broker A and Broker C)
      const brokerB = await spawnBroker('B', portB, 'broker-b.local', tempDir, {
        PEER_PRIVATE_KEY: peerKeyB.privateKeyHex,
        AUTHORIZED_PEERS: `${peerKeyA.publicKeyHex},${peerKeyC.publicKeyHex}`,
      });
      brokers.push(brokerB.proc);

      // Start Broker C (receives from Broker A, and forwards its own local observers to Broker B)
      const brokerC = await spawnBroker('C', portC, 'broker-c.local', tempDir, {
        PEER_PRIVATE_KEY: peerKeyC.privateKeyHex,
        AUTHORIZED_PEERS: peerKeyA.publicKeyHex,
        PEER_1: `ws://127.0.0.1:${portB}|broker-b.local`,
      });
      brokers.push(brokerC.proc);

      // Start Broker A (forwards its local observers to both Broker B and Broker C)
      const brokerA = await spawnBroker('A', portA, 'broker-a.local', tempDir, {
        PEER_PRIVATE_KEY: peerKeyA.privateKeyHex,
        PEER_1: `ws://127.0.0.1:${portB}|broker-b.local`,
        PEER_2: `ws://127.0.0.1:${portC}|broker-c.local`,
      });
      brokers.push(brokerA.proc);

      // Wait until outbound peer bridges report connected in logs
      await new Promise((r) => setTimeout(r, 400));

      // Connect Admin Subscribers to Broker B and Broker C
      const subB = await connectMqttWsClient(`ws://127.0.0.1:${portB}`, 'sub_b', 'admin', 'adminpass123');
      const subC = await connectMqttWsClient(`ws://127.0.0.1:${portC}`, 'sub_c', 'admin', 'adminpass123');
      clients.push(subB, subC);

      await subB.subscribe('meshcore/#');
      await subC.subscribe('meshcore/#');

      // Connect Observer 1 to Broker A
      const obs1JwtA = await createPeerJwt(obs1Key, 'broker-a.local', 3600);
      const obs1ClientA = await connectMqttWsClient(
        `ws://127.0.0.1:${portA}`,
        'obs1_on_a',
        `v1_${obs1Key.publicKeyHex}`,
        obs1JwtA
      );
      clients.push(obs1ClientA);

      // Connect Observer 2 to Broker C
      const obs2JwtC = await createPeerJwt(obs2Key, 'broker-c.local', 3600);
      const obs2ClientC = await connectMqttWsClient(
        `ws://127.0.0.1:${portC}`,
        'obs2_on_c',
        `v1_${obs2Key.publicKeyHex}`,
        obs2JwtC
      );
      clients.push(obs2ClientC);

      // 1. Observer 1 publishes a packet on Broker A
      const topicObs1 = `meshcore/SEA/${obs1Key.publicKeyHex}/packets`;
      const payloadObs1 = JSON.stringify({
        origin_id: obs1Key.publicKeyHex,
        packet_id: 'pkt-from-obs1-on-a',
        SNR: 9.2,
      });
      await obs1ClientA.publish(topicObs1, payloadObs1);

      // 2. Observer 2 publishes a packet on Broker C
      const topicObs2 = `meshcore/PDX/${obs2Key.publicKeyHex}/packets`;
      const payloadObs2 = JSON.stringify({
        origin_id: obs2Key.publicKeyHex,
        packet_id: 'pkt-from-obs2-on-c',
        SNR: 6.5,
      });
      await obs2ClientC.publish(topicObs2, payloadObs2);

      // Wait for propagation across peer bridges
      await new Promise((r) => setTimeout(r, 400));

      // Verify Subscriber on Broker C received Observer 1's packet (from Broker A) and Observer 2's local packet
      const cObs1Packets = subC.received.filter((m) => m.topic === topicObs1);
      const cObs2Packets = subC.received.filter((m) => m.topic === topicObs2);
      assert.strictEqual(cObs1Packets.length, 1, 'Broker C should receive Observer 1 packet from Broker A');
      assert.strictEqual(cObs2Packets.length, 1, 'Broker C should receive Observer 2 local packet');

      // Verify Subscriber on Broker B received Observer 1's packet ONCE (directly from A, NOT re-forwarded by C!)
      // and received Observer 2's packet ONCE (forwarded from C!)
      const bObs1Packets = subB.received.filter((m) => m.topic === topicObs1);
      const bObs2Packets = subB.received.filter((m) => m.topic === topicObs2);
      assert.strictEqual(
        bObs1Packets.length,
        1,
        'Broker B must receive Observer 1 packet exactly ONCE (Broker C must NOT re-forward peer packets)'
      );
      assert.strictEqual(
        bObs2Packets.length,
        1,
        'Broker B must receive Observer 2 packet forwarded from Broker C'
      );

      // 3. Dual-Connected Observer Test: Observer 1 also connects directly to Broker B and publishes the same packet
      const obs1JwtB = await createPeerJwt(obs1Key, 'broker-b.local', 3600);
      const obs1ClientB = await connectMqttWsClient(
        `ws://127.0.0.1:${portB}`,
        'obs1_on_b',
        `v1_${obs1Key.publicKeyHex}`,
        obs1JwtB
      );
      clients.push(obs1ClientB);

      const dualPayload = JSON.stringify({
        origin_id: obs1Key.publicKeyHex,
        packet_id: 'dual-connected-pkt-999',
        SNR: 11.0,
      });

      // Publish on both Broker A (which forwards to B) and directly on Broker B
      await Promise.all([
        obs1ClientA.publish(topicObs1, dualPayload),
        obs1ClientB.publish(topicObs1, dualPayload),
      ]);

      await new Promise((r) => setTimeout(r, 400));

      const bDualMatches = subB.received.filter(
        (m) => m.topic === topicObs1 && m.payload.includes('dual-connected-pkt-999')
      );
      assert.strictEqual(
        bDualMatches.length,
        1,
        'Dual-connected observer publishing identical packet via Broker A and Broker B must be deduplicated on Broker B'
      );
    } finally {
      for (const c of clients) c.close();
      for (const p of brokers) {
        p.kill();
        await new Promise((resolve) => p.once('exit', resolve));
      }
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('puts abusive publisher in temporary mute timeout without disconnecting socket, publishes violators to $SYS, and auto-unmutes after timeout', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-e2e-mute-'));
    const port = await getFreePort();
    const obsKey = await derivePeerKeyPair(crypto.randomBytes(32).toString('hex'));

    const brokers: ChildProcess[] = [];
    const clients: MqttWsClient[] = [];

    try {
      const broker = await spawnBroker('MuteE2E', port, 'mute.local', tempDir, {
        ABUSE_ENFORCEMENT_ENABLED: 'true',
        ABUSE_ANOMALY_THRESHOLD: '1',
        ABUSE_MUTE_DURATION_MS: '1200', // 1.2s timeout for fast E2E verification
        MQTT_SYS_INTERVAL_MS: '300',
      });
      brokers.push(broker.proc);

      const adminSub = await connectMqttWsClient(`ws://127.0.0.1:${port}`, 'admin_mute_sub', 'admin', 'adminpass123');
      clients.push(adminSub);
      await adminSub.subscribe('meshcore/#');
      await adminSub.subscribe('$SYS/broker/security/abuse_detector/violators');

      const obsJwt = await createPeerJwt(obsKey, 'mute.local', 3600);
      const obsClient = await connectMqttWsClient(
        `ws://127.0.0.1:${port}`,
        'obs_violator',
        `v1_${obsKey.publicKeyHex}`,
        obsJwt
      );
      clients.push(obsClient);

      const topic = `meshcore/SEA/${obsKey.publicKeyHex}/packets`;

      // 1. Publish oversized raw packet (>255 bytes) -> triggers anomaly #1 -> mutes publisher for 1.2s
      await obsClient.publish(
        topic,
        JSON.stringify({
          origin_id: obsKey.publicKeyHex,
          packet_id: 'oversized-trigger',
          raw: 'AA'.repeat(300),
        })
      );

      // 2. Immediately publish a normal packet while muted -> must be silently dropped, socket stays open
      await obsClient.publish(
        topic,
        JSON.stringify({
          origin_id: obsKey.publicKeyHex,
          packet_id: 'dropped-during-timeout',
        })
      );

      // Wait 500ms for $SYS snapshot tick
      await new Promise((r) => setTimeout(r, 500));

      assert.strictEqual(obsClient.ws.readyState, WebSocket.OPEN, 'Muted publisher WebSocket must remain open');
      const deliveredDuringMute = adminSub.received.filter((m) => m.topic === topic);
      assert.strictEqual(deliveredDuringMute.length, 0, 'Packets from muted publisher must be silently dropped');

      // 3. Verify $SYS/broker/security/abuse_detector/violators lists the violator
      const violatorMsgs = adminSub.received.filter(
        (m) => m.topic === '$SYS/broker/security/abuse_detector/violators'
      );
      assert.ok(violatorMsgs.length > 0, 'Expected $SYS/broker/security/abuse_detector/violators to be published');
      const latestViolators = JSON.parse(violatorMsgs[violatorMsgs.length - 1].payload);
      assert.strictEqual(latestViolators.length, 1);
      assert.strictEqual(latestViolators[0].publicKey, obsKey.publicKeyHex);
      assert.strictEqual(latestViolators[0].status, 'muted');
      assert.ok(latestViolators[0].mutedUntil > 0);

      // 4. Wait for the 1.2s mute timeout to expire, then publish on the SAME open connection
      await new Promise((r) => setTimeout(r, 900));
      await obsClient.publish(
        topic,
        JSON.stringify({
          origin_id: obsKey.publicKeyHex,
          packet_id: 'allowed-after-timeout-expired',
        })
      );

      await new Promise((r) => setTimeout(r, 250));
      const deliveredAfterExpiry = adminSub.received.filter(
        (m) => m.topic === topic && m.payload.includes('allowed-after-timeout-expired')
      );
      assert.strictEqual(
        deliveredAfterExpiry.length,
        1,
        `Publisher must automatically unmute after timeout expires without reconnecting. Broker logs:\n${broker.logs()}`
      );
    } finally {
      for (const c of clients) c.close();
      for (const p of brokers) {
        p.kill();
        await new Promise((resolve) => p.once('exit', resolve));
      }
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
