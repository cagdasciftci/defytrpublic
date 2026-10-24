import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ErrorCode } from '../src/errors.js';
import { JURISDICTIONS, MessageSigning, Requirement, selfHostedRequirement } from '../src/jurisdictions.js';

const invalid = e => e.code === ErrorCode.INVALID_POLICY_INPUT;

test('EU: control assessment only when the amount exceeds EUR 1 000 (Art. 14(5): "exceeding")', () => {
  assert.equal(selfHostedRequirement({ jurisdiction: 'EU', amount: '1000', currency: 'EUR' }).requirement, Requirement.RISK_BASED);
  assert.equal(selfHostedRequirement({ jurisdiction: 'EU', amount: '1000.000000000000000001', currency: 'EUR' }).requirement, Requirement.CONTROL_ASSESSMENT);
  const r = selfHostedRequirement({ jurisdiction: 'EU', amount: 1500, currency: 'EUR' });
  assert.equal(r.aboveThreshold, true);
  assert.equal(r.messageSigning, MessageSigning.LISTED);
});

test('UK: threshold is inclusive (reg. 64G: "equal to or exceeds"), and stays risk-based', () => {
  const at = selfHostedRequirement({ jurisdiction: 'UK', amount: '800', currency: 'GBP' });
  const below = selfHostedRequirement({ jurisdiction: 'UK', amount: '799.99', currency: 'GBP' });
  assert.equal(at.aboveThreshold, true);
  assert.equal(below.aboveThreshold, false);
  assert.equal(at.requirement, Requirement.RISK_BASED);
});

test('CH: control check at any amount; TR: declaration at any amount', () => {
  assert.equal(selfHostedRequirement({ jurisdiction: 'CH', amount: '0.01' }).requirement, Requirement.CONTROL_ASSESSMENT);
  assert.equal(selfHostedRequirement({ jurisdiction: 'CH' }).aboveThreshold, null);
  assert.equal(selfHostedRequirement({ jurisdiction: 'TR', amount: '1000000', currency: 'TRY' }).requirement, Requirement.DECLARATION);
  assert.equal(selfHostedRequirement({ jurisdiction: 'TR' }).messageSigning, MessageSigning.NOT_PRESCRIBED);
});

test('never converts currencies: a threshold profile rejects any other currency', () => {
  assert.throws(() => selfHostedRequirement({ jurisdiction: 'EU', amount: '5000', currency: 'USD' }), invalid);
  assert.throws(() => selfHostedRequirement({ jurisdiction: 'EU', amount: '5000' }), invalid);
});

test('rejects unknown jurisdictions, prototype keys and malformed amounts', () => {
  for (const jurisdiction of ['DE', 'eu', '__proto__', 'toString', undefined]) {
    assert.throws(() => selfHostedRequirement({ jurisdiction, amount: '1', currency: 'EUR' }), invalid, String(jurisdiction));
  }
  for (const amount of ['-1', '1e3', '01', '1.', '', ' 1', NaN, Infinity, -5, null, {}]) {
    assert.throws(() => selfHostedRequirement({ jurisdiction: 'EU', amount, currency: 'EUR' }), invalid, String(amount));
  }
  assert.throws(() => selfHostedRequirement(), invalid);
});

test('every profile is frozen, dated and cites at least one https source', () => {
  for (const p of Object.values(JURISDICTIONS)) {
    assert.ok(Object.isFrozen(p) && Object.isFrozen(p.sources));
    assert.match(p.asOf, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(p.sources.length > 0);
    for (const s of p.sources) assert.match(s.url, /^https:\/\//);
    assert.ok(Object.values(Requirement).includes(p.aboveThreshold));
    assert.ok(Object.values(Requirement).includes(p.belowThreshold));
  }
});
