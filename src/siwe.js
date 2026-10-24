import { ErrorCode, ProofError } from './errors.js';
import { isValidNonce } from './nonce.js';

export const STATEMENT =
  'I confirm I control this wallet for a Travel Rule transfer. This signature does not authorize any payment.';

const DOMAIN_RE = /^[a-z0-9.-]+(:\d{1,5})?$/i;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const URN_SAFE_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(field) {
  throw new ProofError(ErrorCode.INVALID_CHALLENGE_INPUT, `invalid challenge field: ${field}`);
}

function isoUtc(date, field) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) fail(field);
  return date.toISOString();
}

function validateCommon(fields) {
  const { domain, nonce, issuedAt, expirationTime, requestId, vaspId, transferReference, direction } = fields;
  if (typeof domain !== 'string' || !DOMAIN_RE.test(domain)) fail('domain');
  if (!isValidNonce(nonce)) fail('nonce');
  if (typeof requestId !== 'string' || !UUID_RE.test(requestId)) fail('requestId');
  if (typeof vaspId !== 'string' || !URN_SAFE_RE.test(vaspId)) fail('vaspId');
  if (typeof transferReference !== 'string' || !URN_SAFE_RE.test(transferReference)) fail('transferReference');
  if (direction !== 'inbound' && direction !== 'outbound') fail('direction');
  const issued = isoUtc(issuedAt, 'issuedAt');
  const expires = isoUtc(expirationTime, 'expirationTime');
  if (expirationTime.getTime() <= issuedAt.getTime()) fail('expirationTime');
  return { issued, expires };
}

const tail = ({ domain, nonce, requestId, vaspId, transferReference, direction }, issued, expires, networkLine) => [
  '',
  STATEMENT,
  '',
  `URI: https://${domain}/travel-rule/wallet-proof`,
  'Version: 1',
  networkLine,
  `Nonce: ${nonce}`,
  `Issued At: ${issued}`,
  `Expiration Time: ${expires}`,
  `Request ID: ${requestId}`,
  'Resources:',
  `- urn:travel-rule:vasp:${vaspId}`,
  `- urn:travel-rule:transfer:${transferReference}`,
  `- urn:travel-rule:direction:${direction}`,
];

/**
 * Render the EIP-4361 (Sign-In with Ethereum) message that binds a wallet-control proof
 * to one VASP, chain, address, transfer and single-use nonce (SPEC §3).
 *
 * The server must store these fields and re-render the message at verification time;
 * a client-supplied message string is never the source of truth (threat T8).
 *
 * `address` must already be EIP-55 checksummed (checksumming needs keccak-256 and is
 * done by the EVM verifier module before calling this function).
 */
export function buildSiweMessage(fields) {
  const f = fields ?? {};
  const { issued, expires } = validateCommon(f);
  if (typeof f.address !== 'string' || !ADDRESS_RE.test(f.address)) fail('address');
  if (!Number.isSafeInteger(f.chainId) || f.chainId < 1) fail('chainId');
  return [`${f.domain} wants you to sign in with your Ethereum account:`, f.address, ...tail(f, issued, expires, `Chain ID: ${f.chainId}`)].join('\n');
}

const BTC_ADDRESS_RE = /^(?:bc|tb|bcrt)1[02-9ac-hj-np-z]{6,87}$/;
const BTC_NETWORKS = new Set(['mainnet', 'testnet', 'regtest']);

/**
 * Render the Bitcoin challenge text signed with BIP-322 (SPEC §3). Same bound fields as the EVM
 * message; `Network` replaces `Chain ID`. `address` must be a lower-case segwit address that the
 * caller has already decoded and checksum-validated.
 */
export function buildBitcoinChallengeMessage(fields) {
  const f = fields ?? {};
  const { issued, expires } = validateCommon(f);
  if (typeof f.address !== 'string' || !BTC_ADDRESS_RE.test(f.address)) fail('address');
  if (!BTC_NETWORKS.has(f.network)) fail('network');
  return [`${f.domain} wants you to prove control of this Bitcoin address:`, f.address, ...tail(f, issued, expires, `Network: bitcoin:${f.network}`)].join('\n');
}
