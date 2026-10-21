import { describe, it } from 'node:test';
import assert from 'node:assert';
import { parsePeerString, PeerConfig } from '../src/config';
import { isForwardableTopic, PeerBridgeManager, validatePeerPacket } from '../src/peer-bridge';

describe('Peer Configuration Parsing', () => {
  it('parses standard ws URL with port', () => {
    const peer = parsePeerString('ws://guy-a.example.com:8883:myuser:mypass', 'peer_1');
    assert.ok(peer);
    assert.strictEqual(peer.id, 'peer_1');
    assert.strictEqual(peer.url, 'ws://guy-a.example.com:8883');
    assert.strictEqual(peer.username, 'myuser');
    assert.strictEqual(peer.password, 'mypass');
  });

  it('parses wss URL with path and port', () => {
    const peer = parsePeerString('wss://broker.example.com:443/mqtt:peer_guy:token_123', 'peer_2');
    assert.ok(peer);
    assert.strictEqual(peer.id, 'peer_2');
    assert.strictEqual(peer.url, 'wss://broker.example.com:443/mqtt');
    assert.strictEqual(peer.username, 'peer_guy');
    assert.strictEqual(peer.password, 'token_123');
  });

  it('prepends ws:// if scheme is missing', () => {
    const peer = parsePeerString('guy-b.local:8883:u:p', 'peer_3');
    assert.ok(peer);
    assert.strictEqual(peer.url, 'ws://guy-b.local:8883');
    assert.strictEqual(peer.username, 'u');
    assert.strictEqual(peer.password, 'p');
  });

  it('returns null on invalid formats', () => {
    assert.strictEqual(parsePeerString('nocolons', 'p'), null);
    assert.strictEqual(parsePeerString('one:colon', 'p'), null);
    assert.strictEqual(parsePeerString('::', 'p'), null);
  });
});

describe('Forwardable Topic Filter', () => {
  const dummyPubkey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';

  it('allows standard forwardable subtopics', () => {
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${dummyPubkey}/packets`), true);
    assert.strictEqual(isForwardableTopic(`meshcore/BOS/${dummyPubkey}/status`), true);
    assert.strictEqual(isForwardableTopic(`meshcore/test/${dummyPubkey}/neighbors`), true);
    assert.strictEqual(isForwardableTopic(`meshcore/PDX/${dummyPubkey}/raw`), true);
  });

  it('blocks sensitive and internal subtopics', () => {
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${dummyPubkey}/internal`), false);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${dummyPubkey}/serial/commands`), false);
    assert.strictEqual(isForwardableTopic(`meshcore/SEA/${dummyPubkey}/serial/responses`), false);
    assert.strictEqual(isForwardableTopic(`$SYS/broker/version`), false);
    assert.strictEqual(isForwardableTopic(`other/topic`), false);
  });
});

describe('Peer Bridge Bounded Queue', () => {
  it('drops oldest packet when queue capacity is reached', () => {
    const dummyConfig: PeerConfig = {
      peers: [
        {
          id: 'test_peer',
          url: 'ws://127.0.0.1:59999',
          username: 'dummy',
          password: 'secret',
        },
      ],
      maxQueueSize: 3,
    };

    const manager = new PeerBridgeManager(dummyConfig);

    try {
      const pubkey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
      const topic = `meshcore/SEA/${pubkey}/packets`;

      // Enqueue 4 packets into a queue of size 3
      manager.forwardLocalPacket({ topic, payload: Buffer.from(JSON.stringify({ id: 1 })) });
      manager.forwardLocalPacket({ topic, payload: Buffer.from(JSON.stringify({ id: 2 })) });
      manager.forwardLocalPacket({ topic, payload: Buffer.from(JSON.stringify({ id: 3 })) });
      manager.forwardLocalPacket({ topic, payload: Buffer.from(JSON.stringify({ id: 4 })) });

      const stats = manager.getPeerStats();
      assert.strictEqual(stats['test_peer'].queued, 3);
      assert.strictEqual(stats['test_peer'].dropped, 1);
    } finally {
      manager.shutdown();
    }
  });

  it('ignores non-forwardable packets from entering queue', () => {
    const dummyConfig: PeerConfig = {
      peers: [
        {
          id: 'test_peer',
          url: 'ws://127.0.0.1:59999',
          username: 'dummy',
          password: 'secret',
        },
      ],
      maxQueueSize: 5,
    };

    const manager = new PeerBridgeManager(dummyConfig);

    try {
      const pubkey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
      manager.forwardLocalPacket({
        topic: `meshcore/SEA/${pubkey}/internal`,
        payload: Buffer.from('{"secret":"pii"}'),
      });

      const stats = manager.getPeerStats();
      assert.strictEqual(stats['test_peer'].queued, 0);
    } finally {
      manager.shutdown();
    }
  });
});

describe('Peer Packet Validation (Role 4 Inbound)', () => {
  const pubkey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
  const mockIataValidator = (code: string) => code === 'SEA' || code === 'BOS';

  it('validates and normalizes valid peer packet', () => {
    const payload = JSON.stringify({ origin_id: pubkey, raw: '1234' });
    const result = validatePeerPacket(`meshcore/sea/${pubkey.toLowerCase()}/packets`, payload, mockIataValidator);

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.normalizedTopic, `meshcore/SEA/${pubkey}/packets`);
    assert.strictEqual(result.originId, pubkey);
  });

  it('allows "test" region without IATA check', () => {
    const payload = JSON.stringify({ origin_id: pubkey });
    const result = validatePeerPacket(`meshcore/TEST/${pubkey}/status`, payload, () => false);

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.normalizedTopic, `meshcore/test/${pubkey}/status`);
  });

  it('rejects placeholder XXX region', () => {
    const payload = JSON.stringify({ origin_id: pubkey });
    const result = validatePeerPacket(`meshcore/XXX/${pubkey}/packets`, payload, mockIataValidator);

    assert.strictEqual(result.valid, false);
    assert.ok(result.error?.includes('XXX'));
  });

  it('rejects missing or invalid origin_id', () => {
    const payloadMissing = JSON.stringify({ raw: '1234' });
    const resultMissing = validatePeerPacket(`meshcore/SEA/${pubkey}/packets`, payloadMissing, mockIataValidator);
    assert.strictEqual(resultMissing.valid, false);

    const payloadInvalid = JSON.stringify({ origin_id: 'short' });
    const resultInvalid = validatePeerPacket(`meshcore/SEA/${pubkey}/packets`, payloadInvalid, mockIataValidator);
    assert.strictEqual(resultInvalid.valid, false);
  });

  it('rejects unauthorized subtopics like internal and serial', () => {
    const payload = JSON.stringify({ origin_id: pubkey });
    const resultInternal = validatePeerPacket(`meshcore/SEA/${pubkey}/internal`, payload, mockIataValidator);
    assert.strictEqual(resultInternal.valid, false);

    const resultSerial = validatePeerPacket(`meshcore/SEA/${pubkey}/serial/commands`, payload, mockIataValidator);
    assert.strictEqual(resultSerial.valid, false);
  });
});
