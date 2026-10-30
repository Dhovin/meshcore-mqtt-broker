import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
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

describe('Scale Test: 200+ Concurrent Authenticated Observers', () => {
  it('authenticates 200 concurrent Ed25519 observers and routes 200 concurrent telemetry packets with 0 drops', async () => {
    const OBSERVER_COUNT = 200;
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-scale-200-'));
    const dbPath = join(tempDir, 'abuse.db');
    const wsPort = await getFreePort();

    const broker = spawn(process.execPath, ['dist/server.js'], {
      env: {
        ...process.env,
        LOG_LEVEL: 'info',
        MQTT_WS_PORT: String(wsPort),
        MQTT_TCP_PORT: String(wsPort + 1000),
        ENABLE_TCP_MQTT: 'false',
        MQTT_HOST: '127.0.0.1',
        AUTH_EXPECTED_AUDIENCE: 'scale.meshcore.local',
        HTTP_REDIRECT_URL: '',
        MQTT_MAX_PACKET_BYTES: '65536',
        MQTT_SYS_INTERVAL_MS: '5000',
        SUBSCRIBER_MAX_CONNECTIONS_DEFAULT: '5',
        SUBSCRIBER_1: 'admin:adminpass123:1:5',
        ABUSE_ENFORCEMENT_ENABLED: 'true',
        ABUSE_MUTE_DURATION_MS: '14400000',
        ABUSE_DUPLICATE_WINDOW_SIZE: '100',
        ABUSE_DUPLICATE_WINDOW_MS: '300000',
        ABUSE_DUPLICATE_THRESHOLD: '10',
        ABUSE_MAX_DUPLICATES_PER_PACKET: '5',
        ABUSE_DUPLICATE_RATE_THRESHOLD: '0.3',
        ABUSE_DUPLICATE_RATE_WINDOW_MS: '300000',
        ABUSE_BUCKET_CAPACITY: '20',
        ABUSE_BUCKET_REFILL_RATE: '3',
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

    const sockets: WebSocket[] = [];

    try {
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Broker startup timed out')), 8000);
        let out = '';
        broker.stdout?.on('data', (chunk) => {
          out += chunk.toString();
          if (out.includes('Ready to accept connections')) {
            clearTimeout(timeout);
            resolve();
          }
        });
        broker.on('exit', (code) => {
          clearTimeout(timeout);
          reject(new Error(`Broker exited with code ${code}: ${out}`));
        });
      });

      // 1. Connect Admin subscriber listening to meshcore/SEA/+/packets
      let receivedPackets = 0;
      let allReceivedResolve: (() => void) | null = null;
      const allReceivedPromise = new Promise<void>((resolve) => {
        allReceivedResolve = resolve;
      });

      const subWs = new WebSocket(`ws://127.0.0.1:${wsPort}`, ['mqtt']);
      sockets.push(subWs);
      const subParser = mqttPacket.parser({ protocolVersion: 4 });

      await new Promise<void>((resolve, reject) => {
        subParser.on('packet', (pkt: any) => {
          if (pkt.cmd === 'connack') {
            assert.strictEqual(pkt.returnCode, 0);
            subWs.send(
              mqttPacket.generate({
                cmd: 'subscribe',
                messageId: 1,
                subscriptions: [{ topic: 'meshcore/SEA/+/packets', qos: 0 }],
              })
            );
          } else if (pkt.cmd === 'suback') {
            resolve();
          } else if (pkt.cmd === 'publish' && pkt.topic.endsWith('/packets')) {
            receivedPackets++;
            if (receivedPackets === OBSERVER_COUNT && allReceivedResolve) {
              allReceivedResolve();
            }
          }
        });
        subWs.on('open', () => {
          subWs.send(
            mqttPacket.generate({
              cmd: 'connect',
              protocolId: 'MQTT',
              protocolVersion: 4,
              clean: true,
              keepalive: 60,
              clientId: 'admin_scale_sub',
              username: 'admin',
              password: Buffer.from('adminpass123', 'utf-8'),
            })
          );
        });
        subWs.on('message', (data) => subParser.parse(Buffer.from(data as any)));
        subWs.on('error', reject);
      });

      // 2. Pre-generate 200 distinct Ed25519 observer identities and JWTs
      const observers = await Promise.all(
        Array.from({ length: OBSERVER_COUNT }, async (_, i) => {
          const seed = crypto.randomBytes(32).toString('hex');
          const keyPair = await derivePeerKeyPair(seed);
          const jwt = await createPeerJwt(keyPair, 'scale.meshcore.local', 3600);
          return { index: i, keyPair, jwt };
        })
      );

      // 3. Connect all 200 observers in batches of 50 to avoid ephemeral OS port exhaustion spikes
      const connectedObservers: Array<{ ws: WebSocket; publicKeyHex: string; index: number }> = [];
      const BATCH_SIZE = 50;

      for (let offset = 0; offset < OBSERVER_COUNT; offset += BATCH_SIZE) {
        const batch = observers.slice(offset, offset + BATCH_SIZE);
        const batchClients = await Promise.all(
          batch.map(
            (obs) =>
              new Promise<{ ws: WebSocket; publicKeyHex: string; index: number }>((resolve, reject) => {
                const ws = new WebSocket(`ws://127.0.0.1:${wsPort}`, ['mqtt']);
                sockets.push(ws);
                const parser = mqttPacket.parser({ protocolVersion: 4 });
                parser.on('packet', (pkt: any) => {
                  if (pkt.cmd === 'connack') {
                    if (pkt.returnCode === 0) {
                      resolve({ ws, publicKeyHex: obs.keyPair.publicKeyHex, index: obs.index });
                    } else {
                      reject(new Error(`Observer ${obs.index} refused with code ${pkt.returnCode}`));
                    }
                  }
                });
                ws.on('open', () => {
                  ws.send(
                    mqttPacket.generate({
                      cmd: 'connect',
                      protocolId: 'MQTT',
                      protocolVersion: 4,
                      clean: true,
                      keepalive: 60,
                      clientId: `obs_${obs.index}`,
                      username: `v1_${obs.keyPair.publicKeyHex}`,
                      password: Buffer.from(obs.jwt, 'utf-8'),
                    })
                  );
                });
                ws.on('message', (data) => parser.parse(Buffer.from(data as any)));
                ws.on('error', reject);
              })
          )
        );
        connectedObservers.push(...batchClients);
      }

      assert.strictEqual(connectedObservers.length, OBSERVER_COUNT, 'All 200 observers must be connected concurrently');

      // 4. All 200 connected observers publish telemetry concurrently
      await Promise.all(
        connectedObservers.map(
          (obs) =>
            new Promise<void>((resolve, reject) => {
              const payload = JSON.stringify({
                origin_id: obs.publicKeyHex,
                seq: obs.index,
                SNR: 7.5,
                RSSI: -88,
                raw: '0102030405060708',
              });
              const pubBuf = mqttPacket.generate({
                cmd: 'publish',
                topic: `meshcore/SEA/${obs.publicKeyHex}/packets`,
                payload: Buffer.from(payload, 'utf-8'),
                qos: 0,
                retain: false,
                dup: false,
              });
              obs.ws.send(pubBuf, (err) => (err ? reject(err) : resolve()));
            })
        )
      );

      // 5. Wait for all 200 packets to arrive at the subscriber
      await Promise.race([
        allReceivedPromise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Received only ${receivedPackets}/${OBSERVER_COUNT} packets`)), 8000)
        ),
      ]);

      assert.strictEqual(receivedPackets, OBSERVER_COUNT, 'Subscriber must receive all 200 observer packets');

      // 6. Verify /health responds quickly while 200 observers are connected
      const healthRes = await fetch(`http://127.0.0.1:${wsPort}/health`);
      assert.strictEqual(healthRes.status, 200);
    } finally {
      for (const s of sockets) {
        try {
          s.terminate();
        } catch {}
      }
      broker.kill();
      await new Promise((resolve) => broker.once('exit', resolve));
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
