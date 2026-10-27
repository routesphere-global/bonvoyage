import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PRODUCTS,
  UTILIZATION_TARGETS,
  balancedOrder,
  buildPlan,
} from './phase2-plan.mjs';

test('a seed produces a deterministic plan identity and schedule', () => {
  const first = buildPlan({seed: 'repeatable'});
  const second = buildPlan({seed: 'repeatable'});
  assert.deepEqual(first, second);
  assert.match(first.plan_id, /^phase2-[a-f0-9]{16}$/);
  assert.notEqual(first.plan_id, buildPlan({seed: 'different'}).plan_id);
});

test('every order contains each product exactly once', () => {
  const plan = buildPlan({seed: 'complete'});
  for (const entry of plan.groups) {
    assert.deepEqual([...entry.product_order].sort(), [...PRODUCTS].sort());
  }
});

test('each four-repetition block balances products across positions', () => {
  const orders = [1, 2, 3, 4]
    .map((repetition) => balancedOrder('balanced', 'curve.1core', repetition));

  for (let position = 0; position < PRODUCTS.length; position += 1) {
    assert.deepEqual(
      orders.map((order) => order[position]).sort(),
      [...PRODUCTS].sort(),
    );
  }
});

test('the execution matrix contains discovery, confirmation, curves, and resilience', () => {
  const plan = buildPlan({
    seed: 'matrix',
    repetitions: 5,
    resilienceRepetitions: 3,
  });
  assert.equal(
    plan.groups.filter((entry) => entry.stage === 'capacity-discovery').length,
    2,
  );
  assert.equal(
    plan.groups.filter((entry) => entry.stage === 'capacity-confirmation').length,
    10,
  );
  assert.equal(
    plan.groups.filter((entry) => entry.stage === 'operating-curve').length,
    10,
  );
  assert.equal(
    plan.groups.filter((entry) => entry.stage === 'resilience').length,
    3,
  );
  for (const entry of plan.groups.filter(
    (candidate) => candidate.stage === 'operating-curve')) {
    assert.deepEqual(entry.utilization_targets, UTILIZATION_TARGETS);
  }
});

test('invalid planning inputs are rejected', () => {
  assert.throws(() => buildPlan({seed: ''}), /seed/);
  assert.throws(() => buildPlan({seed: 'x', repetitions: 4}), /repetitions/);
  assert.throws(
    () => balancedOrder('x', 'context', 0),
    /positive integer/,
  );
});
