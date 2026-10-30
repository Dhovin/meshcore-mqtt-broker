import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { derivePeerKeyPair, loadOrCreatePeerIdentity, createPeerJwt } from '../src/peer-crypto.js';

describe('Peer Crypto & Ed25519 JWT Interconnect', () => {
  it('auto-generates, persists, and reloads peer Ed25519 identity and signs valid MeshCore JWTs', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'meshcore-peer-crypto-'));
    try {
      // 1. Auto-generate identity and persist to peer-identity.json
      const identity1 = await loadOrCreatePeerIdentity(undefined, tempDir);
      assert.strictEqual(identity1.publicKeyHex.length, 64);
      assert.strictEqual(identity1.privateKeyHex.length, 128);
      assert.strictEqual(existsSync(join(tempDir, 'peer-identity.json')), true);

      // 2. Reload from disk and verify deterministic match
      const identity2 = await loadOrCreatePeerIdentity(undefined, tempDir);
      assert.strictEqual(identity2.publicKeyHex, identity1.publicKeyHex);
      assert.strictEqual(identity2.privateKeyHex, identity1.privateKeyHex);

      // 3. Derive from explicit 64-byte privateKeyHex
      const derived = await derivePeerKeyPair(identity1.privateKeyHex);
      assert.strictEqual(derived.publicKeyHex, identity1.publicKeyHex);

      // 4. Sign peer JWT for target audience and verify with @michaelhart/meshcore-decoder
      const jwt = await createPeerJwt(identity1, 'broker-b.meshcore.local', 3600);
      const verified = await verifyAuthToken(jwt, identity1.publicKeyHex);
      assert.ok(verified, 'Expected peer JWT to verify with verifyAuthToken');
      assert.strictEqual(verified.aud, 'broker-b.meshcore.local');
      assert.strictEqual(verified.publicKey, identity1.publicKeyHex);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
