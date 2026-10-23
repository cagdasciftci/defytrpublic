import { randomInt } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export const MIN_NONCE_LENGTH = 16;

/**
 * Cryptographically random alphanumeric nonce (EIP-4361 requires ≥ 8 alphanumeric
 * characters; we require ≥ 16 for ~95 bits of entropy).
 * `crypto.randomInt` uses rejection sampling internally, so every character is uniformly distributed (no modulo bias).
 */
export function generateNonce(length = 22) {
  if (!Number.isInteger(length) || length < MIN_NONCE_LENGTH) {
    throw new RangeError(`nonce length must be an integer ≥ ${MIN_NONCE_LENGTH}`);
  }
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += ALPHABET[randomInt(ALPHABET.length)];
  }
  return out;
}

export function isValidNonce(nonce) {
  return typeof nonce === 'string' && nonce.length >= MIN_NONCE_LENGTH && /^[A-Za-z0-9]+$/.test(nonce);
}
