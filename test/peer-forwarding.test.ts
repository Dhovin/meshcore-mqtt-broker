import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createServer } from 'node:http';
import WebSocket, { WebSocketServer } from 'ws';
import mqttPacket from 'mqtt-packet';
import { parsePeerString, loadAuthorizedPeerKeys } from '../src/config.js';
import { isForwardableTopic, validatePeerPacket, PeerBridgeManager } from '../src/peer-bridge.js';
import { AbuseDetector } from '../src/abuse-detector.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('Peer Configuration Parsing', () => {
  it('parses Ed25519 JWT peer format (url|targetAudience and url:targetAudience)', () => {
    const peer = parsePeerString('wss://broker-b.example.com:8883|broker-b.example.com', 'PEER_1');
    assert.ok(peer);
    assert.strictEqual(peer.id, 'PEER_1');
    assert.strictEqual(peer.url, 'wss://broker-b.example.com:8883');
    assert.strictEqual(peer.targetAudience, 'broker-b.example.com');
    assert.strictEqual(peer.username, undefined);

    const peerColon = parsePeerString('wss://broker-b.example.com:8883:broker-b.example.com', 'PEER_1');
    assert.ok(peerColon);
    assert.strictEqual(peerColon.url, 'wss://broker-b.example.com:8883');
    assert.strictEqual(peerColon.targetAudience, 'broker-b.example.com');
  });

  it('parses Role 4 username/password peer format (url|username|password and url:username:password)', () => {
    const peer = parsePeerString('ws://10.0.0.2:8883|peer_a|secret_pass', 'PEER_2');
    assert.ok(peer);
    assert.strictEqual(peer.id, 'PEER_2');
    assert.strictEqual(peer.url, 'ws://10.0.0.2:8883');
    assert.strictEqual(peer.username, 'peer_a');
    assert.strictEqual(peer.password, 'secret_pass');

    const peerColon = parsePeerString('ws://10.0.0.2:8883:peer_a:secret_pass', 'PEER_2');
    assert.ok(peerColon);
    assert.strictEqual(peerColon.url, 'ws://10.0.0.2:8883');
    assert.strictEqual(peerColon.username, 'peer_a');
    assert.strictEqual(peerColon.password, 'secret_pass');
  });

  it('rejects non-websocket URLs or missing fields', () => {
    assert.strictEqual(parsePeerString('http://broker.example.com|aud', 'PEER_1'), null);
    assert.strictEqual(parsePeerString('wss://broker.example.com', 'PEER_1'), null);
  });

  it('parses AUTHORIZED_PEERS comma-separated 64-hex public keys', () => {
    const key1 = 'a'.repeat(64);
    const key2 = 'B'.repeat(64);
    const prev = process.env.AUTHORIZED_PEERS;
    try {
      process.env.AUTHORIZED_PEERS = `${key1}, ${key2}, invalid_short_key`;
      const keys = loadAuthorizedPeerKeys();
      assert.strictEqual(keys.size, 2);
      assert.strictEqual(keys.has(key1.toUpperCase()), true);
      assert.strictEqual(keys.has(key2), true);
    } finally {
      if (prev === undefined) delete process.env.AUTHORIZED_PEERS;
      else process.env.AUTHORIZED_PEERS = prev;
    }
  });
});

describe('Peer Topic & Packet Validation', () => {
  const validPubKey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';

  it('allows only packets, status, neighbors, and raw subtopics for peer forwarding', () => {
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/packets`), true);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/status`), true);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/neighbors`), true);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/raw`), true);

    // Disallowed topics
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/internal`), false);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/serial/commands`), false);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${validPubKey}/serial/responses`), false);
    assert.strictEqual(isForwardableTopic('$SYS/broker/summary'), false);
  });

  it('validates inbound peer packets and enforces origin_id === topicPublicKey', () => {
    const validPayload = JSON.stringify({
      origin_id: validPubKey.toLowerCase(),
      SNR: 8.5,
      RSSI: -92,
    });

    const res = validatePeerPacket(
      `meshcore/sea/${validPubKey.toLowerCase()}/packets`,
      Buffer.from(validPayload),
      (code) => code === 'SEA'
    );

    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.normalizedTopic, `meshcore/SEA/${validPubKey}/packets`);
    assert.strictEqual(res.originId, validPubKey);
    assert.strictEqual(res.normalizedLocation, 'SEA');
    assert.strictEqual(res.subtopic, 'packets');

    // Mismatched origin_id must be rejected
    const spoofedPayload = JSON.stringify({
      origin_id: 'F'.repeat(64),
    });
    const badRes = validatePeerPacket(
      `meshcore/SEA/${validPubKey}/packets`,
      Buffer.from(spoofedPayload),
      (code) => code === 'SEA'
    );
    assert.strictEqual(badRes.valid, false);
    assert.match(badRes.error!, /origin_id in payload must match/);
  });

  it('recovers and reconnects after HTTP 502 unexpected-response during WebSocket upgrade', async () => {
    let upgradeAttempt = 0;
    const receivedTopics: string[] = [];

    const httpServer = createServer();
    const wss = new WebSocketServer({ noServer: true });

    wss.on('connection', (ws) => {
      const parser = mqttPacket.parser({ protocolVersion: 4 });
      parser.on('packet', (packet: any) => {
        if (packet.cmd === 'connect') {
          ws.send(mqttPacket.generate({ cmd: 'connack', returnCode: 0, sessionPresent: false }));
        } else if (packet.cmd === 'publish') {
          receivedTopics.push(packet.topic);
        }
      });
      ws.on('message', (data: Buffer) => parser.parse(Buffer.from(data as any)));
    });

    httpServer.on('upgrade', (req, socket, head) => {
      upgradeAttempt++;
      if (upgradeAttempt === 1) {
        socket.write('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    });

    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const port = (httpServer.address() as any).port;

    const bridge = new PeerBridgeManager({
      authorizedPeerKeys: new Set(),
      peers: [
        {
          id: 'PEER_1',
          url: `ws://127.0.0.1:${port}`,
          username: 'peer_u',
          password: 'peer_p',
        },
      ],
      maxQueueSize: 100,
      maxQueueBytes: 1024 * 1024,
      queueTtlMs: 60000,
      peerRateLimitPerSec: 500,
    });

    try {
      const topic = `meshcore/SEA/${validPubKey}/packets`;
      bridge.forwardLocalPacket({
        topic,
        payload: JSON.stringify({ origin_id: validPubKey, seq: 1 }),
      });

      // Wait for first 502 attempt + ~1s jittered backoff reconnect + queue drain
      const deadline = Date.now() + 3500;
      while (receivedTopics.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 100));
      }

      assert.ok(upgradeAttempt >= 2, `Expected at least 2 upgrade attempts after 502, got ${upgradeAttempt}`);
      assert.strictEqual(receivedTopics.length, 1, 'Queued packet must be delivered after recovering from 502');
      assert.strictEqual(receivedTopics[0], topic);
    } finally {
      bridge.shutdown();
      wss.close();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    }
  });

  it('drains queue automatically after momentary WebSocket bufferedAmount backpressure spike on a connected link', async () => {
    const receivedPayloads: string[] = [];
    const httpServer = createServer();
    const wss = new WebSocketServer({ server: httpServer });

    wss.on('connection', (ws) => {
      const parser = mqttPacket.parser({ protocolVersion: 4 });
      parser.on('packet', (packet: any) => {
        if (packet.cmd === 'connect') {
          ws.send(mqttPacket.generate({ cmd: 'connack', returnCode: 0, sessionPresent: false }));
        } else if (packet.cmd === 'publish') {
          receivedPayloads.push(packet.payload.toString('utf-8'));
        }
      });
      ws.on('message', (data: Buffer) => parser.parse(Buffer.from(data as any)));
    });

    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const port = (httpServer.address() as any).port;

    const bridge = new PeerBridgeManager({
      authorizedPeerKeys: new Set(),
      peers: [
        {
          id: 'PEER_1',
          url: `ws://127.0.0.1:${port}`,
          username: 'peer_u',
          password: 'peer_p',
        },
      ],
      maxQueueSize: 100,
      maxQueueBytes: 1024 * 1024,
      queueTtlMs: 60000,
      peerRateLimitPerSec: 500,
    });

    try {
      // Wait for initial connection
      const deadline = Date.now() + 2000;
      while (!bridge.getPeerStats().PEER_1?.connected && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.strictEqual(bridge.getPeerStats().PEER_1?.connected, true);

      // Simulate momentary socket backpressure (>512 KiB) on the connected WebSocket
      const peerState = (bridge as any).peers.get('PEER_1');
      let fakeBufferedAmount = 600 * 1024;
      Object.defineProperty(peerState.ws, 'bufferedAmount', {
        get: () => fakeBufferedAmount,
        configurable: true,
      });

      const topic = `meshcore/SEA/${validPubKey}/packets`;
      // First packet arrives while bufferedAmount > 512 KiB -> enters queue
      bridge.forwardLocalPacket({
        topic,
        payload: JSON.stringify({ origin_id: validPubKey, seq: 1 }),
      });
      assert.strictEqual(peerState.queue.length, 1, 'Packet should be queued while bufferedAmount is high');

      // Backpressure clears before the 25ms retry fires, and a second packet arrives
      fakeBufferedAmount = 0;
      bridge.forwardLocalPacket({
        topic,
        payload: JSON.stringify({ origin_id: validPubKey, seq: 2 }),
      });

      // Wait for drain slice to flush both packets
      await new Promise((r) => setTimeout(r, 150));

      assert.strictEqual(peerState.queue.length, 0, 'Queue must drain completely after backpressure clears');
      assert.strictEqual(receivedPayloads.length, 2, 'Both packets must be delivered without stalling');
    } finally {
      bridge.shutdown();
      wss.close();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    }
  });

  it('does not mute observer when recording a burst of peer-forwarded packets ({ fromPeer: true })', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-peer-burst-'));
    try {
      const detector = new AbuseDetector({
        enforcementEnabled: true,
        muteDurationMs: 14400000,
        duplicateWindowSize: 100,
        duplicateWindowMs: 300000,
        duplicateThreshold: 5,
        maxDuplicatesPerPacket: 3,
        duplicateRateThreshold: 0.3,
        duplicateRateWindowMs: 300000,
        bucketCapacity: 5, // Small capacity (5 tokens)
        bucketRefillRate: 1,
        maxPacketSize: 255,
        maxTopicsPerDay: 3,
        anomalyThreshold: 3,
        maxIataChanges24h: 3,
        topicHistorySize: 50,
        topicHistoryWindowMs: 86400000,
        persistencePath: join(tempDir, 'abuse.db'),
        persistenceIntervalMs: 300000,
        stateRetentionMs: 604800000,
      });

      detector.initializeClient(validPubKey, `v1_${validPubKey}`);

      // Simulate 50 backlogged packets arriving from a peer in a single tick
      for (let i = 0; i < 50; i++) {
        const payload = Buffer.from(JSON.stringify({ origin_id: validPubKey, seq: i }));
        const allowed = detector.recordPacket(
          { publicKey: validPubKey },
          { topic: `meshcore/SEA/${validPubKey}/packets`, payload },
          { origin_id: validPubKey, seq: i },
          { fromPeer: true }
        );
        assert.strictEqual(allowed, true);
      }

      const stats = detector.getClientStats(validPubKey);
      assert.ok(stats);
      assert.strictEqual(stats.status, 'allowed', 'Observer must not be muted by peer backlog burst');
      assert.strictEqual(stats.totalPacketsReceived, 50);

      detector.shutdown();
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
