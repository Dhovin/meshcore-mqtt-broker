import { describe, it } from 'node:test';
import assert from 'node:assert';
import { parsePeerString, loadAuthorizedPeerKeys } from '../src/config.js';
import { isForwardableTopic, validatePeerPacket } from '../src/peer-bridge.js';

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
});
