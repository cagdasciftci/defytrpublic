import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

/**
 * Conformance checks for a challenge store implementation (see the contract in `challenges.js`).
 *
 *   await runStoreConformance(() => new MyPostgresStore(pool));
 *
 * `createStore` must return a fresh, empty store each call. For a durable store, also run
 * `concurrentConsumers` against two separate connections/processes in your own integration tests.
 */
export async function runStoreConformance(createStore) {
  const fixture = (overrides = {}) => ({
    challengeId: randomUUID(),
    scheme: 'eip191-siwe',
    domain: 'vasp.example',
    vaspId: 'demo-vasp',
    address: '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23',
    chainId: 1,
    transferReference: 'transfer-001',
    direction: 'outbound',
    nonce: 'AbCdEf0123456789XyZ012',
    issuedAt: '2026-11-01T10:00:00.000Z',
    expirationTime: '2026-11-01T10:10:00.000Z',
    ...overrides,
  });
  const before = new Date('2026-11-01T10:05:00.000Z');
  const after = new Date('2026-11-01T10:10:00.000Z');

  // 1. insert-only, no upsert, no reset
  {
    const store = await createStore();
    const c = fixture();
    await store.save(c);
    await assert.rejects(store.save(c), 'duplicate save must fail');
    assert.equal(await store.consume(c.challengeId, before), true);
    await assert.rejects(store.save({ ...c }), 'save must not reset a consumed challenge');
    assert.equal((await store.get(c.challengeId)).state, 'consumed');
  }

  // 2. get returns a copy, and null for unknown ids
  {
    const store = await createStore();
    const c = fixture();
    await store.save(c);
    const got = await store.get(c.challengeId);
    assert.equal(got.state, 'issued');
    for (const key of Object.keys(c)) assert.deepEqual(got[key], c[key], `field ${key} round-trips`);
    try {
      got.address = '0x0000000000000000000000000000000000000000';
    } catch {
      /* frozen copies are fine */
    }
    assert.equal((await store.get(c.challengeId)).address, c.address, 'mutating a copy must not change the store');
    assert.equal(await store.get(randomUUID()), null);
  }

  // 3. consume: single use, expiry-aware, unknown ids fail
  {
    const store = await createStore();
    const c = fixture();
    await store.save(c);
    assert.equal(await store.consume(c.challengeId, after), false, 'consume at/after expiry must fail');
    assert.equal((await store.get(c.challengeId)).state, 'issued', 'failed consume must not change state');
    assert.equal(await store.consume(c.challengeId, before), true);
    assert.equal(await store.consume(c.challengeId, before), false, 'second consume must fail');
    assert.equal(await store.consume(randomUUID(), before), false);
  }

  // 4. concurrency: exactly one winner
  {
    const store = await createStore();
    const c = fixture();
    await store.save(c);
    const results = await Promise.all(Array.from({ length: 20 }, () => store.consume(c.challengeId, before)));
    assert.equal(results.filter(Boolean).length, 1, 'exactly one concurrent consume may succeed');
  }
}
