// Local demo: node examples/demo/server.js, then open http://localhost:8787
// No framework, no database: an in-memory store, one VASP, one process. Not for production.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  MemoryChallengeStore,
  ProofError,
  reverifyEvidence,
  SCHEME_BIP322_SIMPLE,
  SCHEME_EIP191_SIWE,
  selfHostedRequirement,
  WalletProofService,
} from '../../src/index.js';

const VASP_ID = 'demo-vasp';
const page = new URL('./index.html', import.meta.url);

const MAX_BODY = 16 * 1024;
async function body(req) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw new ProofError('INVALID_CHALLENGE_INPUT', 'request too large');
    chunks.push(c);
  }
  const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
}

const send = (res, status, data) => {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(data));
};

export function createDemoServer({ port }) {
  const DOMAIN = `localhost:${port}`;
  const evidenceKey = randomBytes(32);
  const service = new WalletProofService({ store: new MemoryChallengeStore(), domain: DOMAIN, vaspId: VASP_ID, evidenceKey, evidenceKeyId: 'demo-1' });
  const routes = {
    'POST /api/challenges': async b => {
      const scheme = b.scheme === SCHEME_BIP322_SIMPLE ? SCHEME_BIP322_SIMPLE : SCHEME_EIP191_SIWE;
      const requirement = selfHostedRequirement({ jurisdiction: b.jurisdiction, amount: b.amount, currency: b.currency });
      const issued = await service.issue({
        scheme,
        address: b.address,
        chainId: scheme === SCHEME_EIP191_SIWE ? Number(b.chainId) : undefined,
        transferReference: `demo-${Date.now()}`,
        direction: b.direction === 'inbound' ? 'inbound' : 'outbound',
      });
      return { ...issued, requirement };
    },
    'POST /api/verify': async b => {
      const evidence = await service.verify({ challengeId: b.challengeId, signature: b.signature });
      const offline = reverifyEvidence(evidence, { domain: DOMAIN, vaspId: VASP_ID, evidenceKey });
      return { evidence, offline };
    },
  };

  return createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        });
        res.end(await readFile(page));
        return;
      }
      const key = `${req.method} ${req.url}`;
      const handler = Object.hasOwn(routes, key) ? routes[key] : null;
      if (!handler) return send(res, 404, { error: 'not found' });
      return send(res, 200, await handler(await body(req)));
    } catch (e) {
      if (e instanceof ProofError) return send(res, 422, { code: e.code, message: e.message });
      if (e instanceof SyntaxError) return send(res, 400, { code: 'BAD_JSON' });
      console.error(e);
      return send(res, 500, { code: 'INTERNAL' });
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8787);
  createDemoServer({ port }).listen(port, '127.0.0.1', () => console.log(`wallet-ownership-proof demo on http://localhost:${port}`));
}
