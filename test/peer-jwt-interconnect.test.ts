import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { derivePeerKeyPair, loadOrCreatePeerIdentity, createPeerJwt } from '../src/peer-crypto';
import { parsePeerString, loadAuthorizedPeerKeys } from '../src/config';
import { PeerBridgeManager } from '../src/peer-bridge';

describe('Peer Cryptography & Identity Management', () => {
  it('derives keypair from 32-byte seed (64 hex chars)', async () => {
    // 32-byte hex seed (all zeros except last byte)
    const seed = '0000000000000000000000000000000000000000000000000000000000000001';
    const keyPair = await derivePeerKeyPair(seed);

    assert.strictEqual(keyPair.privateKeyHex.length, 128); // 64 bytes
    assert.strictEqual(keyPair.publicKeyHex.length, 64);   // 32 bytes
  });

  it('rejects invalid private key lengths', async () => {
    await assert.rejects(async () => {
      await derivePeerKeyPair('tooshort');
    }, /Invalid private key length/);
  });

  it('auto-generates and persists peer identity to disk', async () => {
    const testDataDir = path.join(process.cwd(), 'test-temp-data');
    if (fs.existsSync(testDataDir)) {
      fs.rmSync(testDataDir, { recursive: true, force: true });
    }

    try {
      const identity1 = await loadOrCreatePeerIdentity(undefined, testDataDir);
      assert.ok(identity1.publicKeyHex);
      assert.ok(identity1.privateKeyHex);
      assert.strictEqual(identity1.publicKeyHex.length, 64);

      const filePath = path.join(testDataDir, 'peer-identity.json');
      assert.strictEqual(fs.existsSync(filePath), true);

      // Reloading from disk should return identical keys
      const identity2 = await loadOrCreatePeerIdentity(undefined, testDataDir);
      assert.strictEqual(identity2.publicKeyHex, identity1.publicKeyHex);
      assert.strictEqual(identity2.privateKeyHex, identity1.privateKeyHex);
    } finally {
      if (fs.existsSync(testDataDir)) {
        fs.rmSync(testDataDir, { recursive: true, force: true });
      }
    }
  });

  it('creates valid MeshCore JWT tokens verifiable by verifyAuthToken', async () => {
    const seed = 'A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0';
    const keyPair = await derivePeerKeyPair(seed);

    const token = await createPeerJwt(keyPair, 'test-target-broker', 3600);
    assert.ok(token);

    // Verify token using standard meshcore-decoder verifyAuthToken
    const payload = await verifyAuthToken(token, keyPair.publicKeyHex);
    assert.ok(payload);
    assert.strictEqual(payload.aud, 'test-target-broker');
    assert.strictEqual(payload.publicKey, keyPair.publicKeyHex);
  });

  it('rejects expired JWT tokens', async () => {
    const seed = 'A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0';
    const keyPair = await derivePeerKeyPair(seed);

    // Create token expired 10 seconds ago
    const expiredToken = await createPeerJwt(keyPair, 'test-target-broker', -10);
    const payload = await verifyAuthToken(expiredToken, keyPair.publicKeyHex);
    assert.strictEqual(payload, null);
  });
});

describe('Peer Configuration (JWT Audience Format)', () => {
  it('parses ws URL with port and target audience', () => {
    const target = parsePeerString('ws://broker-b.example.com:8883:target_aud_b', 'peer_1');
    assert.ok(target);
    assert.strictEqual(target.id, 'peer_1');
    assert.strictEqual(target.url, 'ws://broker-b.example.com:8883');
    assert.strictEqual(target.targetAudience, 'target_aud_b');
  });

  it('parses wss URL with path and target audience', () => {
    const target = parsePeerString('wss://hub.example.com/mqtt:hub_audience', 'peer_2');
    assert.ok(target);
    assert.strictEqual(target.id, 'peer_2');
    assert.strictEqual(target.url, 'wss://hub.example.com/mqtt');
    assert.strictEqual(target.targetAudience, 'hub_audience');
  });

  it('loads authorized peer keys from environment variables', () => {
    const origEnv = process.env.AUTHORIZED_PEERS;
    const testKey1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const testKey2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

    try {
      process.env.AUTHORIZED_PEERS = `${testKey1}, ${testKey2.toLowerCase()}, invalid_short_key`;
      const keys = loadAuthorizedPeerKeys();

      assert.strictEqual(keys.size, 2);
      assert.strictEqual(keys.has(testKey1), true);
      assert.strictEqual(keys.has(testKey2), true);
    } finally {
      if (origEnv !== undefined) {
        process.env.AUTHORIZED_PEERS = origEnv;
      } else {
        delete process.env.AUTHORIZED_PEERS;
      }
    }
  });
});

describe('Peer Bridge Manager with JWT Identity', () => {
  it('initializes outbound client with JWT credentials and queues packets', async () => {
    const seed = '0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20';
    const identity = await derivePeerKeyPair(seed);

    const config = {
      peers: [
        {
          id: 'test_peer',
          url: 'ws://127.0.0.1:59998',
          targetAudience: 'mock_target_aud',
        },
      ],
      authorizedPeerKeys: new Set<string>(),
      maxQueueSize: 5,
    };

    const manager = new PeerBridgeManager(config, identity);

    try {
      const pubkey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
      const topic = `meshcore/SEA/${pubkey}/packets`;
      const payload = Buffer.from(JSON.stringify({ origin_id: pubkey, data: 'test' }));

      manager.forwardLocalPacket({ topic, payload });

      const stats = manager.getPeerStats();
      assert.strictEqual(stats['test_peer'].queued, 1);
      assert.strictEqual(stats['test_peer'].connected, false);
    } finally {
      manager.shutdown();
    }
  });
});
