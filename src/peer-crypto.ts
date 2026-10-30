import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Utils } from '@michaelhart/meshcore-decoder';

export interface PeerKeyPair {
  privateKeyHex: string; // 64-byte orlp format (128 uppercase hex chars)
  publicKeyHex: string;  // 32-byte public key hex (64 uppercase hex chars)
}

/**
 * Derives a full 64-byte private key (128 hex chars) and 32-byte public key (64 hex chars)
 * from either a 32-byte seed (64 hex) or a 64-byte private key (128 hex).
 */
export async function derivePeerKeyPair(keyHex: string): Promise<PeerKeyPair> {
  const cleanHex = keyHex.trim();

  if (cleanHex.length === 64 && /^[0-9A-F]{64}$/i.test(cleanHex)) {
    // 32-byte seed: compute RFC 8032 SHA512 expanded key for orlp/ed25519
    const seedBuf = Buffer.from(cleanHex, 'hex');
    const hash = crypto.createHash('sha512').update(seedBuf).digest();
    hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;
    const fullPrivHex = hash.toString('hex').toUpperCase();
    const pubHex = await Utils.derivePublicKey(fullPrivHex);
    return {
      privateKeyHex: fullPrivHex,
      publicKeyHex: pubHex.toUpperCase(),
    };
  } else if (cleanHex.length === 128 && /^[0-9A-F]{128}$/i.test(cleanHex)) {
    // Full 64-byte key (128 hex chars)
    const upperPriv = cleanHex.toUpperCase();
    const pubHex = await Utils.derivePublicKey(upperPriv);
    return {
      privateKeyHex: upperPriv,
      publicKeyHex: pubHex.toUpperCase(),
    };
  } else {
    throw new Error(
      `Invalid private key length: expected 64 hex chars (32 bytes) or 128 hex chars (64 bytes), got ${cleanHex.length}`
    );
  }
}

/**
 * Loads an existing peer identity from disk or environment, or generates
 * a brand new Ed25519 keypair and persists it to <dataDir>/peer-identity.json.
 */
export async function loadOrCreatePeerIdentity(
  configuredPrivateKey?: string,
  dataDir: string = './data'
): Promise<PeerKeyPair> {
  // 1. If configured in environment, use it directly
  if (configuredPrivateKey && configuredPrivateKey.trim().length > 0) {
    const keyPair = await derivePeerKeyPair(configuredPrivateKey);
    console.log(`[PEER_CRYPTO] Loaded configured peer identity: ${keyPair.publicKeyHex.substring(0, 8)}...`);
    return keyPair;
  }

  // 2. Check if peer-identity.json already exists in dataDir
  const identityFilePath = path.join(dataDir, 'peer-identity.json');
  if (fs.existsSync(identityFilePath)) {
    try {
      const content = fs.readFileSync(identityFilePath, 'utf-8');
      const parsed = JSON.parse(content);
      if (parsed.privateKeyHex && parsed.publicKeyHex) {
        console.log(`[PEER_CRYPTO] Loaded peer identity from ${identityFilePath}: ${parsed.publicKeyHex.substring(0, 8)}...`);
        return {
          privateKeyHex: parsed.privateKeyHex.toUpperCase(),
          publicKeyHex: parsed.publicKeyHex.toUpperCase(),
        };
      }
    } catch (err: any) {
      console.warn(`[PEER_CRYPTO] Failed to read ${identityFilePath}, generating new keypair: ${err.message}`);
    }
  }

  // 3. Auto-generate new 32-byte random seed and derive keypair
  const seed = crypto.randomBytes(32);
  const hash = crypto.createHash('sha512').update(seed).digest();
  hash[0] &= 248;
  hash[31] &= 63;
  hash[31] |= 64;
  const fullPrivHex = hash.toString('hex').toUpperCase();
  const pubHex = await Utils.derivePublicKey(fullPrivHex);

  const identity: PeerKeyPair = {
    privateKeyHex: fullPrivHex,
    publicKeyHex: pubHex.toUpperCase(),
  };

  try {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(identityFilePath, JSON.stringify(identity, null, 2), { encoding: 'utf-8', mode: 0o600 });
    console.log(`[PEER_CRYPTO] Generated and saved new peer identity to ${identityFilePath}: ${identity.publicKeyHex.substring(0, 8)}...`);
  } catch (err: any) {
    console.warn(`[PEER_CRYPTO] Could not save peer identity to disk: ${err.message}`);
  }

  return identity;
}

/**
 * Creates a signed MeshCore JWT authentication token for a target audience.
 *
 * @param identity The sending broker's Ed25519 keypair
 * @param audience The target broker's expected audience (e.g., target broker domain or audience claim)
 * @param ttlSeconds Token expiration duration in seconds (defaults to 24 hours: 86400)
 */
export async function createPeerJwt(
  identity: PeerKeyPair,
  audience: string,
  ttlSeconds: number = 86400
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: audience,
    exp: now + ttlSeconds,
    iat: now,
    publicKey: identity.publicKeyHex,
  };

  return Utils.createAuthToken(payload, identity.privateKeyHex, identity.publicKeyHex);
}
