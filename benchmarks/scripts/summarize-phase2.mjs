#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

const PRODUCTS = ['bonvoyage', 'envoy', 'nginx', 'haproxy'];
const CORE_COUNTS = [1, 2];
const UTILIZATION_TARGETS = [0.5, 0.7, 0.8, 0.9, 0.95];
const RESILIENCE_TARGETS = {overload: 1.2, recovery: 0.7, 'connection-churn': 0.5};

function median(values) {
  if (values.length === 0) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 1
    ? ordered[middle]
    : (ordered[middle - 1] + ordered[middle]) / 2;
}

function maximum(values, fallback = null) {
  return values.length === 0 ? fallback : Math.max(...values);
}

function maximumDeviationPercent(values) {
  const center = median(values);
  if (center === null || center === 0) return null;
  return maximum(values.map((value) => Math.abs(value - center) / center * 100));
}

function resultKey(result) {
  return [
    result.product.name,
    result.execution.gateway_cores,
    result.execution.stage,
    result.execution.repetition,
    result.execution.utilization_target ?? 'none',
  ].join(':');
}

function scheduledResults(results, plan, runId, environmentSha256) {
  const settings = plan.settings;
  if (!Number.isInteger(settings?.repetitions) || settings.repetitions < 5 ||
      !Number.isInteger(settings.resilience_repetitions) ||
      settings.resilience_repetitions < 1 ||
      !isDeepStrictEqual(settings.utilization_targets, UTILIZATION_TARGETS) ||
      !Array.isArray(plan.products) ||
      !isDeepStrictEqual([...plan.products].sort(), [...PRODUCTS].sort()) ||
      !Array.isArray(plan.groups)) {
    throw new Error('invalid Phase 2 plan settings');
  }
  const groups = new Map();
  const identities = new Set();
  for (const group of plan.groups) {
    const identity = [group.stage, group.gateway_cores, group.repetition].join(':');
    const repetitions = group.stage === 'resilience' ? settings.resilience_repetitions
      : group.stage === 'capacity-discovery' ? 1 : settings.repetitions;
    if (!['capacity-discovery', 'capacity-confirmation', 'operating-curve', 'resilience']
      .includes(group.stage) || !CORE_COUNTS.includes(group.gateway_cores) ||
        (group.stage === 'resilience' && group.gateway_cores !== 2) ||
        !Number.isInteger(group.repetition) || group.repetition < 1 ||
        group.repetition > repetitions || typeof group.key !== 'string' || !group.key ||
        !Array.isArray(group.product_order) ||
        !isDeepStrictEqual([...group.product_order].sort(), [...PRODUCTS].sort()) ||
        !isDeepStrictEqual(group.utilization_targets,
          group.stage === 'operating-curve' ? UTILIZATION_TARGETS : undefined) ||
        groups.has(group.key) || identities.has(identity)) {
      throw new Error(`invalid or duplicate Phase 2 schedule group: ${group.key}`);
    }
    groups.set(group.key, group);
    identities.add(identity);
  }
  if (groups.size !== 2 * (1 + 2 * settings.repetitions) + settings.resilience_repetitions) {
    throw new Error('incomplete Phase 2 plan schedule');
  }

  const attempts = new Set();
  const eligible = new Map();
  for (const result of results) {
    const execution = result.execution;
    const group = groups.get(execution.schedule_key);
    const stage = execution.stage;
    const resilience = Object.hasOwn(RESILIENCE_TARGETS, stage);
    const plannedStage = resilience ? 'resilience'
      : stage === 'capacity-probe' ? 'capacity-discovery' : stage;
    if (!group || result.run_id !== runId ||
        result.environment_sha256 !== environmentSha256 ||
        result.workload_id !== 'http1-keepalive-phase2-baseline' ||
        execution.plan_id !== plan.plan_id || group.stage !== plannedStage ||
        execution.gateway_cores !== group.gateway_cores ||
        execution.repetition !== group.repetition ||
        !Number.isInteger(execution.randomized_position) ||
        group.product_order[execution.randomized_position - 1] !== result.product.name ||
        !Number.isInteger(execution.attempt) || execution.attempt < 1 ||
        typeof result.qualification?.valid !== 'boolean') {
      throw new Error(`out-of-plan result identity: ${resultKey(result)}`);
    }
    const target = execution.utilization_target;
    const targetValid = stage === 'operating-curve' ? group.utilization_targets.includes(target)
      : resilience ? target === RESILIENCE_TARGETS[stage]
      : stage === 'capacity-discovery' ? Number.isFinite(target) && target > 0 && target <= 1.5
      : target === undefined;
    if (!targetValid || result.qualification.intentional_overload !== (stage === 'overload') ||
        (stage === 'recovery' && result.resilience?.recovery_of !== group.key)) {
      throw new Error(`out-of-plan result target or resilience identity: ${resultKey(result)}`);
    }
    const key = resultKey(result);
    const attemptKey = `${key}:${execution.attempt}`;
    if (attempts.has(attemptKey)) {
      throw new Error(`duplicate result identity: ${attemptKey}`);
    }
    attempts.add(attemptKey);
    // Discovery intentionally sweeps multiple valid loads; it never supplies a
    // confirmation/curve/resilience repetition. Other slots need one valid attempt.
    if (['capacity-probe', 'capacity-discovery'].includes(stage) || !result.qualification.valid) {
      continue;
    }
    if (eligible.has(key)) throw new Error(`ambiguous valid attempts: ${key}`);
    eligible.set(key, result);
  }
  return [...eligible.values()];
}

function accepted(results, product, cores, stage) {
  return results.filter((result) =>
    result.product.name === product &&
    result.execution.gateway_cores === cores &&
    result.execution.stage === stage &&
    result.qualification.valid);
}

function summarizeConfirmation(results, product, cores, thresholds) {
  const runs = accepted(results, product, cores, 'capacity-confirmation');
  const rates = runs.map((result) => result.metrics.successful_rps);
  const p999Values = runs.map((result) => result.metrics.latency_ms.p999);
  const errors = runs.map((result) => result.metrics.error_rate);
  const offeredRates = runs.map((result) => result.execution.offered_rps);
  const supportUse = runs.flatMap((result) => [
    result.metrics.load_generator_capacity_percent,
    result.metrics.upstream_capacity_percent,
  ]);
  const sustainableRps = median(rates);
  const rateVariation = maximumDeviationPercent(rates);

  return {
    valid_repetitions: runs.length,
    offered_rps: median(offeredRates),
    sustainable_successful_rps: sustainableRps,
    rps_per_core: sustainableRps === null ? null : sustainableRps / cores,
    maximum_rate_deviation_percent: rateVariation,
    median_p999_ms: median(p999Values),
    maximum_p999_ms: maximum(p999Values),
    maximum_error_rate: maximum(errors),
    maximum_support_role_capacity_percent: maximum(supportUse),
    gates: {
      repetitions_pass: runs.length >= thresholds.minimumRepetitions,
      repeatability_pass: rateVariation !== null &&
        rateVariation <= thresholds.maximumVariationPercent,
      latency_pass: p999Values.length > 0 &&
        maximum(p999Values) <= thresholds.latencyCeilingMs,
      errors_pass: errors.length > 0 &&
        maximum(errors) <= thresholds.maximumErrorRate,
      support_roles_pass: supportUse.length > 0 &&
        maximum(supportUse) <= thresholds.maximumSupportCapacityPercent,
    },
  };
}

function summarizeCurve(results, product, cores, thresholds) {
  const runs = accepted(results, product, cores, 'operating-curve');
  const points = {};

  for (const target of UTILIZATION_TARGETS) {
    const matching = runs.filter((result) =>
      result.execution.utilization_target === target);
    const rates = matching.map((result) => result.metrics.successful_rps);
    points[String(target)] = {
      valid_repetitions: matching.length,
      median_successful_rps: median(rates),
      maximum_rate_deviation_percent: maximumDeviationPercent(rates),
      median_p50_ms: median(matching.map((result) => result.metrics.latency_ms.p50)),
      median_p95_ms: median(matching.map((result) => result.metrics.latency_ms.p95)),
      median_p99_ms: median(matching.map((result) => result.metrics.latency_ms.p99)),
      median_p999_ms: median(matching.map((result) => result.metrics.latency_ms.p999)),
      maximum_p999_ms: maximum(matching.map(
        (result) => result.metrics.latency_ms.p999)),
      maximum_error_rate: maximum(matching.map(
        (result) => result.metrics.error_rate)),
      maximum_support_role_capacity_percent: maximum(matching.flatMap(
        (result) => [
          result.metrics.load_generator_capacity_percent,
          result.metrics.upstream_capacity_percent,
        ])),
    };
  }

  const pointValues = Object.values(points);
  return {
    points,
    gates: {
      repetitions_pass: pointValues.every((point) =>
        point.valid_repetitions >= thresholds.minimumRepetitions),
      repeatability_pass: pointValues.every((point) =>
        point.maximum_rate_deviation_percent !== null &&
        point.maximum_rate_deviation_percent <= thresholds.maximumVariationPercent),
      latency_pass: pointValues.every((point) =>
        point.maximum_p999_ms !== null &&
        point.maximum_p999_ms <= thresholds.latencyCeilingMs),
      errors_pass: pointValues.every((point) =>
        point.maximum_error_rate !== null &&
        point.maximum_error_rate <= thresholds.maximumErrorRate),
      support_roles_pass: pointValues.every((point) =>
        point.maximum_support_role_capacity_percent !== null &&
        point.maximum_support_role_capacity_percent <=
          thresholds.maximumSupportCapacityPercent),
    },
  };
}

function summarizeResilience(results, product, thresholds) {
  const overload = accepted(results, product, 2, 'overload');
  const overloadObserved = overload.filter((result) =>
    result.metrics.error_rate > thresholds.maximumErrorRate ||
    result.metrics.latency_ms.p999 > thresholds.latencyCeilingMs ||
    result.metrics.successful_rps < result.execution.offered_rps * 0.98);
  const recovery = accepted(results, product, 2, 'recovery');
  const churn = accepted(results, product, 2, 'connection-churn');
  const repetitions = new Set([
    ...overload.map((result) => result.execution.repetition),
    ...recovery.map((result) => result.execution.repetition),
    ...churn.map((result) => result.execution.repetition),
  ]);

  let completeSets = 0;
  let processRestarted = false;
  for (const repetition of repetitions) {
    const overloadRun = overload.find((result) =>
      result.execution.repetition === repetition);
    const recoveryRun = recovery.find((result) =>
      result.execution.repetition === repetition);
    const churnRun = churn.find((result) =>
      result.execution.repetition === repetition);
    if (overloadRun && recoveryRun && churnRun) {
      const ids = [overloadRun, recoveryRun, churnRun]
        .map((result) => result.resilience?.gateway_container_id)
        .filter(Boolean);
      const sameContainer = ids.length === 3 && new Set(ids).size === 1;
      const sameAttempt = new Set([overloadRun, recoveryRun, churnRun]
        .map((result) => result.execution.attempt)).size === 1;
      const restarted = [overloadRun, recoveryRun, churnRun]
        .some((result) => result.resilience?.process_restarted !== false);
      processRestarted ||= restarted || !sameContainer;
      if (sameContainer && sameAttempt && !restarted) completeSets += 1;
    }
  }

  const rssGrowth = churn.map((result) =>
    result.resilience?.rss_growth_bytes ?? Number.POSITIVE_INFINITY);
  const rssSlope = churn.map((result) =>
    result.resilience?.rss_slope_bytes_per_second ?? Number.POSITIVE_INFINITY);

  return {
    complete_repetitions: completeSets,
    overload_runs: overload.length,
    overload_observed_runs: overloadObserved.length,
    valid_recovery_runs: recovery.length,
    valid_churn_runs: churn.length,
    process_restarted: processRestarted,
    maximum_churn_rss_growth_bytes: maximum(rssGrowth),
    maximum_churn_rss_slope_bytes_per_second: maximum(rssSlope),
    gates: {
      repetitions_pass: completeSets >= thresholds.resilienceRepetitions,
      overload_observed_pass:
        overloadObserved.length >= thresholds.resilienceRepetitions,
      recovery_pass: recovery.length >= thresholds.resilienceRepetitions,
      churn_pass: churn.length >= thresholds.resilienceRepetitions &&
        maximum(rssGrowth) <= thresholds.maximumChurnRssGrowthBytes &&
        maximum(rssSlope) <= thresholds.maximumChurnRssSlopeBytesPerSecond,
      no_restart_pass: !processRestarted &&
        completeSets >= thresholds.resilienceRepetitions,
    },
  };
}

function allGatesPass(section) {
  return Object.values(section.gates).every(Boolean);
}

export function summarizePhase2({
  results,
  environment,
  plan,
  runId,
  environmentSha256,
  thresholds = {},
}) {
  const limits = {
    minimumRepetitions: 5,
    resilienceRepetitions: 3,
    latencyCeilingMs: 4,
    maximumErrorRate: 0.001,
    maximumVariationPercent: 5,
    maximumSupportCapacityPercent: 80,
    minimumAdvantagePercent: 20,
    optimizationAdvantagePercent: 5,
    minimumScalingEfficiency: 0.85,
    maximumChurnRssGrowthBytes: 32 * 1024 * 1024,
    maximumChurnRssSlopeBytesPerSecond: 256 * 1024,
    ...thresholds,
  };

  const eligibleResults = scheduledResults(results, plan, runId, environmentSha256);
  // Complete the declared schedule as well as meeting the canonical minimum.
  limits.minimumRepetitions = Math.max(limits.minimumRepetitions, plan.settings.repetitions);
  limits.resilienceRepetitions = Math.max(
    limits.resilienceRepetitions, plan.settings.resilience_repetitions);

  const products = {};
  for (const product of PRODUCTS) {
    const coreProfiles = {};
    for (const cores of CORE_COUNTS) {
      coreProfiles[String(cores)] = {
        confirmation: summarizeConfirmation(eligibleResults, product, cores, limits),
        operating_curve: summarizeCurve(eligibleResults, product, cores, limits),
      };
    }
    const oneCore = coreProfiles['1'].confirmation.sustainable_successful_rps;
    const twoCore = coreProfiles['2'].confirmation.sustainable_successful_rps;
    const scalingEfficiency = oneCore && twoCore
      ? twoCore / (2 * oneCore)
      : null;
    products[product] = {
      core_profiles: coreProfiles,
      two_core_scaling_efficiency: scalingEfficiency,
      resilience: summarizeResilience(eligibleResults, product, limits),
    };
  }

  const advantage = {};
  for (const cores of CORE_COUNTS) {
    const bonvoyageRpsPerCore = products.bonvoyage
      .core_profiles[String(cores)].confirmation.rps_per_core;
    const comparatorRates = PRODUCTS.slice(1).map((product) => ({
      product,
      rps_per_core: products[product]
        .core_profiles[String(cores)].confirmation.rps_per_core,
    })).filter((entry) => entry.rps_per_core !== null);
    comparatorRates.sort((left, right) => right.rps_per_core - left.rps_per_core);
    const strongest = comparatorRates[0] ?? null;
    advantage[String(cores)] = {
      strongest_comparator: strongest?.product ?? null,
      strongest_comparator_rps_per_core: strongest?.rps_per_core ?? null,
      bonvoyage_rps_per_core: bonvoyageRpsPerCore,
      advantage_percent: strongest && bonvoyageRpsPerCore !== null
        ? (bonvoyageRpsPerCore / strongest.rps_per_core - 1) * 100
        : null,
    };
  }

  const confirmationPass = PRODUCTS.every((product) => CORE_COUNTS.every(
    (cores) => allGatesPass(products[product]
      .core_profiles[String(cores)].confirmation)));
  const curvesPass = PRODUCTS.every((product) => CORE_COUNTS.every(
    (cores) => allGatesPass(products[product]
      .core_profiles[String(cores)].operating_curve)));
  const scalingPass = products.bonvoyage.two_core_scaling_efficiency !== null &&
    products.bonvoyage.two_core_scaling_efficiency >= limits.minimumScalingEfficiency;
  const resiliencePass = PRODUCTS.every((product) =>
    allGatesPass(products[product].resilience));
  const advantages = Object.values(advantage)
    .map((entry) => entry.advantage_percent);
  const advantageComplete = advantages.every((value) => value !== null);
  const minimumAdvantage = advantageComplete ? Math.min(...advantages) : null;
  const advantagePass = minimumAdvantage !== null &&
    minimumAdvantage >= limits.minimumAdvantagePercent;
  const evidenceComplete = confirmationPass && curvesPass && resiliencePass;
  const publicationAuthorized =
    environment.qualification?.publication_authorized === true &&
    environment.qualification?.evidence_class === 'native-qualification';

  let decision = 'incomplete';
  if (evidenceComplete && scalingPass && minimumAdvantage !== null) {
    if (advantagePass) decision = 'pass';
    else if (minimumAdvantage >= limits.optimizationAdvantagePercent) {
      decision = 'optimization-cycle';
    } else {
      decision = 'architecture-review';
    }
  } else if (evidenceComplete && !scalingPass) {
    decision = 'architecture-review';
  }

  const phase2ExitPass = publicationAuthorized && decision === 'pass';
  return {
    schema_version: 1,
    run_id: runId,
    workload_id: 'http1-keepalive-phase2-baseline',
    plan_id: plan.plan_id,
    environment_sha256: environmentSha256,
    evidence_class: environment.qualification?.evidence_class ?? 'local-functional',
    thresholds: limits,
    result_documents: results.length,
    products,
    advantage,
    gates: {
      confirmation_pass: confirmationPass,
      operating_curves_pass: curvesPass,
      support_roles_pass: PRODUCTS.every((product) => CORE_COUNTS.every(
        (cores) => products[product].core_profiles[String(cores)]
          .confirmation.gates.support_roles_pass &&
          products[product].core_profiles[String(cores)]
            .operating_curve.gates.support_roles_pass)),
      minimum_bonvoyage_advantage_percent: minimumAdvantage,
      bonvoyage_advantage_pass: advantagePass,
      bonvoyage_two_core_scaling_efficiency:
        products.bonvoyage.two_core_scaling_efficiency,
      scaling_pass: scalingPass,
      resilience_pass: resiliencePass,
      evidence_complete: evidenceComplete,
      publication_authorized: publicationAuthorized,
      decision,
      phase2_exit_pass: phase2ExitPass,
    },
  };
}

function formatNumber(value, digits = 2) {
  return value === null || !Number.isFinite(value) ? 'n/a' : value.toFixed(digits);
}

export function renderMarkdown(summary) {
  const lines = [
    `# Phase 2 Competitive Evidence: ${summary.run_id}`,
    '',
    `- Evidence class: \`${summary.evidence_class}\``,
    `- Plan: \`${summary.plan_id}\``,
    `- Result documents: \`${summary.result_documents}\``,
    `- Decision: **${summary.gates.decision}**`,
    `- Canonical Phase 2 exit: \`${summary.gates.phase2_exit_pass}\``,
    '',
    '| Product | 1-core sustainable RPS | 2-core sustainable RPS | 2-core efficiency |',
    '| --- | ---: | ---: | ---: |',
  ];
  for (const product of PRODUCTS) {
    const record = summary.products[product];
    lines.push(
      `| ${product} | ${formatNumber(record.core_profiles['1'].confirmation.sustainable_successful_rps)} | ` +
      `${formatNumber(record.core_profiles['2'].confirmation.sustainable_successful_rps)} | ` +
      `${formatNumber(record.two_core_scaling_efficiency === null
        ? null
        : record.two_core_scaling_efficiency * 100)}% |`,
    );
  }
  lines.push('', '| Gateway cores | Strongest comparator | BonVoyage advantage |');
  lines.push('| ---: | --- | ---: |');
  for (const cores of CORE_COUNTS) {
    const record = summary.advantage[String(cores)];
    lines.push(
      `| ${cores} | ${record.strongest_comparator ?? 'n/a'} | ` +
      `${formatNumber(record.advantage_percent)}% |`,
    );
  }
  lines.push('', '## Gate result', '');
  lines.push(`- Confirmed sustainable capacities: \`${summary.gates.confirmation_pass}\``);
  lines.push(`- Complete operating curves: \`${summary.gates.operating_curves_pass}\``);
  lines.push(`- Support-role headroom: \`${summary.gates.support_roles_pass}\``);
  lines.push(`- BonVoyage performance advantage: \`${summary.gates.bonvoyage_advantage_pass}\``);
  lines.push(`- BonVoyage scaling efficiency: \`${summary.gates.scaling_pass}\``);
  lines.push(`- Overload, recovery, and churn: \`${summary.gates.resilience_pass}\``);
  lines.push('');
  lines.push('This report is derived from immutable raw result documents. ' +
    'A local-functional report cannot authorize a public performance claim.');
  return `${lines.join('\n')}\n`;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if ([
      '--raw-dir',
      '--summary',
      '--report',
      '--verify-summary',
      '--verify-report',
    ].includes(key) && value) {
      options[key.slice(2).replace('-', '_')] = value;
      index += 1;
    } else {
      throw new Error(`unknown or incomplete argument: ${key}`);
    }
  }
  if (!options.raw_dir) throw new Error('--raw-dir is required');
  const verificationMode = Boolean(options.verify_summary || options.verify_report);
  if (verificationMode) {
    if (!options.verify_summary || !options.verify_report ||
        options.summary || options.report) {
      throw new Error(
        'verification requires --verify-summary and --verify-report only',
      );
    }
  } else if (!options.summary || !options.report) {
    throw new Error('generation requires --summary and --report');
  }
  return options;
}

export function summarizeRawDirectory(rawDirectory) {
  const directoryEntries = fs.readdirSync(rawDirectory);
  const files = directoryEntries
    .filter((name) => name.endsWith('.result.json'))
    .sort();
  if (files.length === 0) throw new Error('no Phase 2 result documents found');
  const environmentFiles = directoryEntries
    .filter((name) => name.endsWith('.environment.json'));
  const planFiles = directoryEntries
    .filter((name) => name.endsWith('.plan.json'));
  if (environmentFiles.length !== 1 || planFiles.length !== 1) {
    throw new Error('raw directory must contain one environment and one plan document');
  }
  const environmentPath = path.join(rawDirectory, environmentFiles[0]);
  const environmentBytes = fs.readFileSync(environmentPath);
  const environmentSha256 = createHash('sha256')
    .update(environmentBytes)
    .digest('hex');
  const results = files.map((name) => readJson(path.join(rawDirectory, name)));
  const runIds = new Set(results.map((result) => result.run_id));
  if (runIds.size !== 1) throw new Error('result documents contain multiple run IDs');
  return summarizePhase2({
    results,
    environment: readJson(environmentPath),
    plan: readJson(path.join(rawDirectory, planFiles[0])),
    runId: [...runIds][0],
    environmentSha256,
  });
}

function publishOutputs(outputs) {
  const staged = [];
  const published = [];
  try {
    for (const {destination, content} of outputs) {
      const directory = fs.mkdtempSync(path.join(path.dirname(destination), '.phase2-summary-'));
      const temporary = path.join(directory, 'output');
      staged.push({directory, temporary, destination});
      fs.writeFileSync(temporary, content, {flag: 'wx'});
    }
    // Exclusive links publish complete files without overwriting retained data.
    // The summary is the last publication step, after its companion report.
    for (const {temporary, destination} of staged) {
      fs.linkSync(temporary, destination);
      published.push(destination);
    }
  } catch (error) {
    for (const destination of published.reverse()) fs.unlinkSync(destination);
    throw error;
  } finally {
    for (const {directory} of staged) fs.rmSync(directory, {recursive: true, force: true});
  }
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  if (!options.verify_summary) {
    if (path.resolve(options.summary) === path.resolve(options.report)) {
      throw new Error('summary and report require distinct fresh output paths');
    }
    for (const output of [options.summary, options.report]) {
      if (fs.lstatSync(output, {throwIfNoEntry: false})) {
        throw new Error(`refusing existing output ${output}; use fresh paths or --verify-summary/--verify-report`);
      }
    }
  }
  const summary = summarizeRawDirectory(options.raw_dir);
  const report = renderMarkdown(summary);
  if (options.verify_summary) {
    if (!isDeepStrictEqual(readJson(options.verify_summary), summary)) {
      throw new Error(`${options.verify_summary} differs from derived evidence`);
    }
    if (fs.readFileSync(options.verify_report, 'utf8') !== report) {
      throw new Error(`${options.verify_report} differs from derived evidence`);
    }
    return;
  }
  publishOutputs([
    {destination: options.report, content: report},
    {destination: options.summary, content: `${JSON.stringify(summary, null, 2)}\n`},
  ]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase2-summary: ${error.message}\n`);
    process.exitCode = 1;
  }
}
