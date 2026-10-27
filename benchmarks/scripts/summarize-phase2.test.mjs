import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';

import {buildPlan} from './phase2-plan.mjs';
import {renderMarkdown, summarizePhase2} from './summarize-phase2.mjs';

const plan = buildPlan({seed: 'test'});
const resilienceTargets = {overload: 1.2, recovery: 0.7, 'connection-churn': 0.5};

function bindSchedule(item, selectedPlan = plan) {
  const execution = item.execution;
  const plannedStage = execution.stage in resilienceTargets ? 'resilience'
    : execution.stage === 'capacity-probe' ? 'capacity-discovery' : execution.stage;
  const group = selectedPlan.groups.find((entry) => entry.stage === plannedStage &&
    entry.gateway_cores === execution.gateway_cores && entry.repetition === execution.repetition);
  execution.plan_id = selectedPlan.plan_id;
  execution.schedule_key = group.key;
  execution.randomized_position = group.product_order.indexOf(item.product.name) + 1;
  if (execution.stage === 'recovery') item.resilience.recovery_of = group.key;
  return item;
}

const capacities = {
  bonvoyage: {1: 120000, 2: 230000},
  envoy: {1: 90000, 2: 174000},
  nginx: {1: 95000, 2: 184000},
  haproxy: {1: 85000, 2: 164000},
};

function result({
  product,
  cores,
  stage,
  repetition,
  utilizationTarget,
  rps,
  valid = true,
  containerId = `${product}000000000000`,
  rssGrowth = 1024,
  rssSlope = 10,
}) {
  return bindSchedule({
    schema_version: 2,
    fixture: false,
    run_id: 'phase2-test',
    workload_id: 'http1-keepalive-phase2-baseline',
    environment_sha256: '0'.repeat(64),
    product: {name: product},
    execution: {
      gateway_cores: cores,
      stage,
      repetition,
      attempt: 1,
      offered_rps: rps,
      ...((utilizationTarget ?? resilienceTargets[stage]) === undefined
        ? {}
        : {utilization_target: utilizationTarget ?? resilienceTargets[stage]}),
    },
    metrics: {
      successful_rps: rps,
      error_rate: 0,
      latency_ms: {p50: 0.5, p95: 1, p99: 1.5, p999: 2},
      load_generator_capacity_percent: 30,
      upstream_capacity_percent: 35,
    },
    qualification: {valid, intentional_overload: stage === 'overload'},
    resilience: {
      gateway_container_id: containerId,
      process_restarted: false,
      rss_growth_bytes: rssGrowth,
      rss_slope_bytes_per_second: rssSlope,
    },
  });
}

function passingResults() {
  const results = [];
  for (const [product, profiles] of Object.entries(capacities)) {
    for (const cores of [1, 2]) {
      for (let repetition = 1; repetition <= 5; repetition += 1) {
        results.push(result({
          product,
          cores,
          stage: 'capacity-confirmation',
          repetition,
          rps: profiles[cores],
        }));
        for (const target of [0.5, 0.7, 0.8, 0.9, 0.95]) {
          results.push(result({
            product,
            cores,
            stage: 'operating-curve',
            repetition,
            utilizationTarget: target,
            rps: profiles[cores] * target,
          }));
        }
      }
    }
    for (let repetition = 1; repetition <= 3; repetition += 1) {
      const containerId = `${product}${String(repetition).padStart(12, '0')}`;
      for (const stage of ['overload', 'recovery', 'connection-churn']) {
        const resilienceResult = result({
          product,
          cores: 2,
          stage,
          repetition,
          rps: profiles[2] * 0.7,
          containerId,
        });
        if (stage === 'overload') {
          resilienceResult.execution.offered_rps = profiles[2] * 1.2;
        }
        results.push(resilienceResult);
      }
    }
  }
  return results;
}

function summarize(results = passingResults(), selectedPlan = plan) {
  return summarizePhase2({
    results,
    environment: {
      qualification: {
        evidence_class: 'native-qualification',
        publication_authorized: true,
      },
    },
    plan: selectedPlan,
    runId: 'phase2-test',
    environmentSha256: '0'.repeat(64),
  });
}

test('passing evidence closes the competitive gate', () => {
  const summary = summarize();
  assert.equal(summary.gates.decision, 'pass');
  assert.equal(summary.gates.phase2_exit_pass, true);
  assert.equal(summary.advantage['1'].strongest_comparator, 'nginx');
  assert.ok(summary.gates.minimum_bonvoyage_advantage_percent >= 20);
  assert.ok(summary.gates.bonvoyage_two_core_scaling_efficiency >= 0.85);
  assert.match(renderMarkdown(summary), /Canonical Phase 2 exit: `true`/);
});

test('a moderate advantage selects an optimization cycle', () => {
  const results = passingResults();
  for (const item of results) {
    if (item.product.name === 'bonvoyage') {
      item.metrics.successful_rps *= 0.88;
      item.execution.offered_rps *= 0.88;
    }
  }
  const summary = summarize(results);
  assert.equal(summary.gates.decision, 'optimization-cycle');
  assert.equal(summary.gates.phase2_exit_pass, false);
});

test('missing repetitions produce incomplete evidence', () => {
  const results = passingResults().filter((item) => !(
    item.product.name === 'envoy' &&
    item.execution.stage === 'operating-curve' &&
    item.execution.repetition === 5
  ));
  const summary = summarize(results);
  assert.equal(summary.gates.operating_curves_pass, false);
  assert.equal(summary.gates.decision, 'incomplete');
});

test('process replacement fails resilience even when recovery traffic succeeds', () => {
  const results = passingResults();
  const recovery = results.find((item) =>
    item.product.name === 'haproxy' && item.execution.stage === 'recovery');
  recovery.resilience.gateway_container_id = 'replacement000000';
  const summary = summarize(results);
  assert.equal(summary.products.haproxy.resilience.gates.no_restart_pass, false);
  assert.equal(summary.gates.resilience_pass, false);
  assert.equal(summary.gates.decision, 'incomplete');
});

test('resilience fails when the overload point never crosses capacity', () => {
  const results = passingResults();
  for (const item of results.filter(
    (candidate) => candidate.execution.stage === 'overload')) {
    item.execution.offered_rps = item.metrics.successful_rps;
  }
  const summary = summarize(results);
  assert.equal(
    summary.products.bonvoyage.resilience.gates.overload_observed_pass,
    false,
  );
  assert.equal(summary.gates.resilience_pass, false);
});

test('duplicate result identities are rejected', () => {
  const results = passingResults();
  results.push(structuredClone(results[0]));
  assert.throws(() => summarize(results), /duplicate result identity/);
});

test('review trigger: attempts cannot replace scheduled confirmation or curve repetitions', () => {
  const results = passingResults();
  for (const item of results.filter((item) =>
    ['capacity-confirmation', 'operating-curve'].includes(item.execution.stage))) {
    item.execution.attempt = item.execution.repetition;
    item.execution.repetition = 1;
    bindSchedule(item);
  }
  assert.throws(() => summarize(results), /ambiguous valid attempts/);
});

for (const stage of ['capacity-confirmation', 'operating-curve', ...Object.keys(resilienceTargets)]) {
  test(`${stage}: multiple valid attempts are ambiguous in either order`, () => {
    const results = passingResults();
    const duplicate = structuredClone(results.find((item) => item.execution.stage === stage));
    duplicate.execution.attempt = 2;
    results.push(duplicate);
    assert.throws(() => summarize(results), /ambiguous valid attempts/);
    assert.throws(() => summarize(results.reverse()), /ambiguous valid attempts/);
  });
}

test('one valid retry after rejected attempts counts once, regardless of input order', () => {
  const results = passingResults();
  const rejected = structuredClone(results[0]);
  rejected.qualification.valid = false;
  results[0].execution.attempt = 2;
  results.push(rejected);
  const summary = summarize(results);
  assert.equal(summary.products.bonvoyage.core_profiles['1'].confirmation.valid_repetitions, 5);
  assert.equal(summary.gates.phase2_exit_pass, true);
  assert.deepEqual(summarize(results.reverse()), summary);
});

test('rejected attempts do not fill missing scheduled repetitions', () => {
  const results = passingResults();
  results[0].qualification.valid = false;
  const retry = structuredClone(results[0]);
  retry.execution.attempt = 2;
  results.push(retry);
  const summary = summarize(results);
  assert.equal(summary.products.bonvoyage.core_profiles['1'].confirmation.valid_repetitions, 4);
  assert.equal(summary.gates.evidence_complete, false);
});

const outOfPlanMutations = {
  'unknown product': (item) => { item.product.name = 'apisix'; },
  'wrong cores': (item) => { item.execution.gateway_cores = 8; },
  'wrong repetition': (item) => { item.execution.repetition = 6; },
  'fractional repetition': (item) => { item.execution.repetition = 1.5; },
  'wrong stage': (item) => { item.execution.stage = 'overload'; },
  'wrong plan': (item) => { item.execution.plan_id = 'phase2-ffffffffffffffff'; },
  'unknown schedule': (item) => { item.execution.schedule_key = 'unknown'; },
  'wrong position': (item) => { item.execution.randomized_position = 0; },
  'missing attempt': (item) => { delete item.execution.attempt; },
  'fractional attempt': (item) => { item.execution.attempt = 1.5; },
  'wrong run': (item) => { item.run_id = 'other-run'; },
  'wrong environment': (item) => { item.environment_sha256 = 'f'.repeat(64); },
  'wrong workload': (item) => { item.workload_id = 'other-workload'; },
  'unexpected target': (item) => { item.execution.utilization_target = 0.5; },
};
for (const [name, mutate] of Object.entries(outOfPlanMutations)) {
  test(`out-of-plan records fail closed even when rejected: ${name}`, () => {
    for (const valid of [true, false]) {
      const results = passingResults();
      results[0].qualification.valid = valid;
      mutate(results[0]);
      assert.throws(() => summarize(results), /out-of-plan result/);
    }
  });
}

test('curve targets must match exactly, with no missing or near-equal aliases', () => {
  for (const target of [undefined, null, 0.50000001, 1.2]) {
    const results = passingResults();
    results.find((item) => item.execution.stage === 'operating-curve')
      .execution.utilization_target = target;
    assert.throws(() => summarize(results), /out-of-plan result target/);
  }
});

test('scheduled repetitions beyond the canonical minimum are required', () => {
  const largerPlan = buildPlan({seed: 'test', repetitions: 6, resilienceRepetitions: 4});
  const results = passingResults().map((item) => bindSchedule(item, largerPlan));
  const summary = summarize(results, largerPlan);
  assert.equal(summary.gates.confirmation_pass, false);
  assert.equal(summary.gates.operating_curves_pass, false);
  assert.equal(summary.gates.resilience_pass, false);
  assert.equal(summary.gates.evidence_complete, false);
});

test('duplicated or missing schedule groups cannot authorize a result', () => {
  const duplicatePlan = structuredClone(plan);
  duplicatePlan.groups.push({...duplicatePlan.groups[0], key: 'alias'});
  assert.throws(() => summarize(passingResults(), duplicatePlan), /duplicate Phase 2 schedule/);
  const incompletePlan = structuredClone(plan);
  incompletePlan.groups.pop();
  assert.throws(() => summarize(passingResults(), incompletePlan), /incomplete Phase 2 plan/);
});

test('discovery sweeps retain multiple valid attempts but never count as repetitions', () => {
  const results = passingResults();
  for (const [index, target] of [0.3, 0.5, 0.7].entries()) {
    const item = result({product: 'bonvoyage', cores: 1, stage: 'capacity-discovery',
      repetition: 1, utilizationTarget: target, rps: 1000});
    item.execution.attempt = index + 1;
    results.push(item);
  }
  const summary = summarize(results);
  assert.equal(summary.gates.phase2_exit_pass, true);
  assert.equal(summary.products.bonvoyage.core_profiles['1'].confirmation.valid_repetitions, 5);
});

test('resilience cannot join stages from different attempts', () => {
  const results = passingResults();
  results.find((item) => item.execution.stage === 'recovery').execution.attempt = 2;
  const summary = summarize(results);
  assert.equal(summary.products.bonvoyage.resilience.complete_repetitions, 2);
  assert.equal(summary.gates.resilience_pass, false);
});

test('a complete resilience retry is eligible only when the other attempts are rejected', () => {
  const results = passingResults();
  const original = results.filter((item) => item.product.name === 'bonvoyage' &&
    item.execution.repetition === 1 && item.execution.stage in resilienceTargets);
  for (const item of original) {
    const rejected = structuredClone(item);
    rejected.qualification.valid = false;
    item.execution.attempt = 2;
    results.push(rejected);
  }
  assert.equal(summarize(results).gates.phase2_exit_pass, true);
});

test('missing or wrong-core resilience evidence cannot fill a scheduled set', () => {
  const results = passingResults();
  const index = results.findIndex((item) => item.execution.stage === 'overload');
  const incomplete = results.filter((_, position) => position !== index);
  assert.equal(summarize(incomplete).gates.resilience_pass, false);
  results[index].execution.gateway_cores = 1;
  assert.throws(() => summarize(results), /out-of-plan result/);
});

test('resilience utilization targets cannot alias an additional attempt', () => {
  const results = passingResults();
  const overload = structuredClone(results.find((item) => item.execution.stage === 'overload'));
  overload.execution.utilization_target = 1.20000001;
  results.push(overload);
  assert.throws(() => summarize(results), /out-of-plan result target/);
});

test('recovery must identify its scheduled resilience group', () => {
  const results = passingResults();
  results.find((item) => item.execution.stage === 'recovery').resilience.recovery_of = 'other';
  assert.throws(() => summarize(results), /resilience identity/);
});

test('an unqualified or unintentional overload is not acceptable resilience evidence', () => {
  const results = passingResults();
  const overload = results.find((item) => item.execution.stage === 'overload');
  overload.qualification.valid = false;
  assert.equal(summarize(results).gates.resilience_pass, false);
  overload.qualification.valid = true;
  overload.qualification.intentional_overload = false;
  assert.throws(() => summarize(results), /resilience identity/);
});

function cliFixture(t, results = passingResults()) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phase2-summary-test-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const rawDirectory = path.join(directory, 'raw');
  fs.mkdirSync(rawDirectory);
  const environment = JSON.stringify({qualification: {
    evidence_class: 'native-qualification', publication_authorized: true,
  }});
  const environmentSha256 = createHash('sha256').update(environment).digest('hex');
  fs.writeFileSync(path.join(rawDirectory, 'test.environment.json'), environment);
  fs.writeFileSync(path.join(rawDirectory, 'test.plan.json'), JSON.stringify(plan));
  for (const [index, item] of results.entries()) {
    item.environment_sha256 = environmentSha256;
    fs.writeFileSync(path.join(rawDirectory, `${index}.result.json`), JSON.stringify(item));
  }
  const summaryPath = path.join(directory, 'new.summary.json');
  const reportPath = path.join(directory, 'new.md');
  const run = ({verify = false, nodeOptions = [], report = reportPath} = {}) => spawnSync(
    process.execPath, [...nodeOptions, fileURLToPath(new URL('./summarize-phase2.mjs', import.meta.url)),
      '--raw-dir', rawDirectory, verify ? '--verify-summary' : '--summary', summaryPath,
      verify ? '--verify-report' : '--report', report], {encoding: 'utf8'});
  return {directory, rawDirectory, summaryPath, reportPath, run};
}

test('CLI publishes a complete fresh pair and verifies it without rewriting', (t) => {
  const fixture = cliFixture(t);
  assert.equal(fixture.run().status, 0);
  const summary = fs.readFileSync(fixture.summaryPath, 'utf8');
  const report = fs.readFileSync(fixture.reportPath, 'utf8');
  assert.equal(JSON.parse(summary).gates.phase2_exit_pass, true);
  assert.equal(fixture.run({verify: true}).status, 0);
  assert.equal(fs.readFileSync(fixture.summaryPath, 'utf8'), summary);
  assert.equal(fs.readFileSync(fixture.reportPath, 'utf8'), report);
  assert.deepEqual(fs.readdirSync(fixture.directory).sort(), ['new.md', 'new.summary.json', 'raw']);
});

test('CLI refuses stale successful output paths; failed verification preserves historical bytes', (t) => {
  const fixture = cliFixture(t);
  assert.equal(fixture.run().status, 0);
  const summary = fs.readFileSync(fixture.summaryPath, 'utf8');
  const report = fs.readFileSync(fixture.reportPath, 'utf8');
  const duplicate = JSON.parse(fs.readFileSync(path.join(fixture.rawDirectory, '0.result.json'), 'utf8'));
  duplicate.execution.attempt = 2;
  fs.writeFileSync(path.join(fixture.rawDirectory, 'retry.result.json'), JSON.stringify(duplicate));
  const generation = fixture.run();
  assert.notEqual(generation.status, 0);
  assert.match(generation.stderr, /refusing existing output/);
  const verification = fixture.run({verify: true});
  assert.notEqual(verification.status, 0);
  assert.match(verification.stderr, /ambiguous valid attempts/);
  assert.equal(fs.readFileSync(fixture.summaryPath, 'utf8'), summary);
  assert.equal(fs.readFileSync(fixture.reportPath, 'utf8'), report);
});

test('CLI rejects ambiguous input without publishing fresh outputs', (t) => {
  const results = passingResults();
  const duplicate = structuredClone(results[0]);
  duplicate.execution.attempt = 2;
  results.push(duplicate);
  const fixture = cliFixture(t, results);
  const response = fixture.run();
  assert.notEqual(response.status, 0);
  assert.match(response.stderr, /ambiguous valid attempts/);
  assert.deepEqual(fs.readdirSync(fixture.directory), ['raw']);
});

test('CLI report destination failures leave no newly published successful summary', (t) => {
  const fixture = cliFixture(t);
  const response = fixture.run({report: path.join(fixture.directory, 'missing', 'new.md')});
  assert.notEqual(response.status, 0);
  assert.equal(fs.existsSync(fixture.summaryPath), false);
  assert.deepEqual(fs.readdirSync(fixture.directory), ['raw']);
});

test('CLI rolls back only its new report if final summary publication fails', (t) => {
  const fixture = cliFixture(t);
  const hook = `import fs from 'node:fs';
    const link = fs.linkSync;
    fs.linkSync = (source, destination) => {
      if (destination.endsWith('new.summary.json')) throw new Error('injected publish failure');
      return link(source, destination);
    };`;
  const response = fixture.run({nodeOptions: ['--import', `data:text/javascript,${encodeURIComponent(hook)}`]});
  assert.notEqual(response.status, 0);
  assert.match(response.stderr, /injected publish failure/);
  assert.deepEqual(fs.readdirSync(fixture.directory), ['raw']);
});

test('CLI never overwrites a pre-existing report or aliases the two destinations', (t) => {
  const fixture = cliFixture(t);
  assert.notEqual(fixture.run({report: fixture.summaryPath}).status, 0);
  fs.writeFileSync(fixture.reportPath, 'retained report');
  assert.notEqual(fixture.run().status, 0);
  assert.equal(fs.existsSync(fixture.summaryPath), false);
  assert.equal(fs.readFileSync(fixture.reportPath, 'utf8'), 'retained report');
});
