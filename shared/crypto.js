/**
 * Chrome Profile Guard — cryptography helpers.
 *
 * Uses the Web Crypto API (globalThis.crypto.subtle), available in MV3
 * service workers, extension pages, and Node 20+ (for the test suite).
 *
 * Design:
 *   secret (PIN/password)
 *     -> PBKDF2-HMAC-SHA256(salt, iterations)
 *       -> 256-bit derived key
 *         -> stored as base64 alongside the salt + parameters
 *
 * The original secret is NEVER stored or logged. Verification re-derives the
 * key from the entered secret and compares in constant time.
 */

import { CRYPTO } from './constants.js';

const subtle = globalThis.crypto?.subtle;

/** @returns {Uint8Array} cryptographically-random bytes. */
export function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** @returns {string} base64 for a byte buffer. */
export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

/** @returns {Uint8Array} bytes for a base64 string. */
export function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Derive raw key bits from a secret using PBKDF2.
 * @param {string} secret
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @returns {Promise<Uint8Array>} derived bits (CRYPTO.KEY_BITS / 8 bytes)
 */
export async function deriveBits(secret, salt, iterations = CRYPTO.ITERATIONS) {
  const keyMaterial = await subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: CRYPTO.ALGO },
    false,
    ['deriveBits'],
  );
  const bits = await subtle.deriveBits(
    { name: CRYPTO.ALGO, salt, iterations, hash: CRYPTO.HASH },
    keyMaterial,
    CRYPTO.KEY_BITS,
  );
  return new Uint8Array(bits);
}

/**
 * Produce a storable credential record from a secret.
 * @param {string} secret
 * @returns {Promise<{salt:string, derivedKey:string, iterations:number, algo:string, hash:string}>}
 */
export async function hashSecret(secret) {
  const salt = randomBytes(CRYPTO.SALT_BYTES);
  const derived = await deriveBits(secret, salt, CRYPTO.ITERATIONS);
  return {
    salt: bytesToBase64(salt),
    derivedKey: bytesToBase64(derived),
    iterations: CRYPTO.ITERATIONS,
    algo: CRYPTO.ALGO,
    hash: CRYPTO.HASH,
  };
}

/**
 * Constant-time byte comparison. Runs in time proportional to the longer
 * input and never short-circuits, so it does not leak how many leading bytes
 * matched (which would translate to "part of your password is correct").
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Verify a secret against a stored credential record.
 * @param {string} secret
 * @param {{salt:string, derivedKey:string, iterations:number}} record
 * @returns {Promise<boolean>}
 */
export async function verifySecret(secret, record) {
  if (!record || !record.salt || !record.derivedKey) return false;
  const salt = base64ToBytes(record.salt);
  const expected = base64ToBytes(record.derivedKey);
  const actual = await deriveBits(secret, salt, record.iterations || CRYPTO.ITERATIONS);
  return constantTimeEqual(actual, expected);
}
