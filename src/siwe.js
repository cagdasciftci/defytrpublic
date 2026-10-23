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
  const {
    domain,
    address,
    chainId,
    nonce,
    issuedAt,
    expirationTime,
    requestId,
    vaspId,
    transferReference,
    direction,
  } = fields ?? {};

  if (typeof domain !== 'string' || !DOMAIN_RE.test(domain)) fail('domain');
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) fail('address');
  if (!Number.isSafeInteger(chainId) || chainId < 1) fail('chainId');
  if (!isValidNonce(nonce)) fail('nonce');
  if (typeof requestId !== 'string' || !UUID_RE.test(requestId)) fail('requestId');
  if (typeof vaspId !== 'string' || !URN_SAFE_RE.test(vaspId)) fail('vaspId');
  if (typeof transferReference !== 'string' || !URN_SAFE_RE.test(transferReference)) fail('transferReference');
  if (direction !== 'inbound' && direction !== 'outbound') fail('direction');

  const issued = isoUtc(issuedAt, 'issuedAt');
  const expires = isoUtc(expirationTime, 'expirationTime');
  if (expirationTime.getTime() <= issuedAt.getTime()) fail('expirationTime');

  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    '',
    STATEMENT,
    '',
    `URI: https://${domain}/travel-rule/wallet-proof`,
    'Version: 1',
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issued}`,
    `Expiration Time: ${expires}`,
    `Request ID: ${requestId}`,
    'Resources:',
    `- urn:travel-rule:vasp:${vaspId}`,
    `- urn:travel-rule:transfer:${transferReference}`,
    `- urn:travel-rule:direction:${direction}`,
  ].join('\n');
}
