#!/usr/bin/env node

import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';

export const PRODUCTS = ['bonvoyage', 'envoy', 'nginx', 'haproxy'];
export const UTILIZATION_TARGETS = [0.5, 0.7, 0.8, 0.9, 0.95];

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function baseOrder(seed, context, block) {
  return [...PRODUCTS].sort((left, right) => {
    const leftHash = digest(`${seed}\0${context}\0${block}\0${left}`);
    const rightHash = digest(`${seed}\0${context}\0${block}\0${right}`);
    return leftHash.localeCompare(rightHash);
  });
}

/**
 * Produces seeded product order while balancing every product across every
 * position during each complete four-repetition block.
 */
export function balancedOrder(seed, context, repetition) {
  if (!Number.isInteger(repetition) || repetition < 1) {
    throw new Error('repetition must be a positive integer');
  }

  const zeroBased = repetition - 1;
  const block = Math.floor(zeroBased / PRODUCTS.length);
  const rotation = zeroBased % PRODUCTS.length;
  const order = baseOrder(seed, context, block);
  return [...order.slice(rotation), ...order.slice(0, rotation)];
}

function group(seed, stage, cores, repetition, extra = {}) {
  const context = `${stage}.${cores}core`;
  return {
    key: `${context}.rep${repetition}`,
    stage,
    gateway_cores: cores,
    repetition,
    ...extra,
    product_order: balancedOrder(seed, context, repetition),
  };
}

export function buildPlan({
  seed,
  repetitions = 5,
  resilienceRepetitions = 3,
} = {}) {
  if (typeof seed !== 'string' || seed.length === 0 || seed.length > 128) {
    throw new Error('seed must contain between 1 and 128 characters');
  }
  if (!Number.isInteger(repetitions) || repetitions < 5) {
    throw new Error('repetitions must be an integer of at least 5');
  }
  if (!Number.isInteger(resilienceRepetitions) || resilienceRepetitions < 1) {
    throw new Error('resilience repetitions must be a positive integer');
  }

  const groups = [];
  for (const cores of [1, 2]) {
    groups.push(group(seed, 'capacity-discovery', cores, 1));
    for (let repetition = 1; repetition <= repetitions; repetition += 1) {
      groups.push(group(seed, 'capacity-confirmation', cores, repetition));
      groups.push(group(seed, 'operating-curve', cores, repetition, {
        utilization_targets: UTILIZATION_TARGETS,
      }));
    }
  }
  for (let repetition = 1;
    repetition <= resilienceRepetitions;
    repetition += 1) {
    groups.push(group(seed, 'resilience', 2, repetition));
  }

  const body = {
    schema_version: 1,
    seed,
    products: PRODUCTS,
    settings: {
      repetitions,
      resilience_repetitions: resilienceRepetitions,
      utilization_targets: UTILIZATION_TARGETS,
    },
    groups,
  };
  return {
    ...body,
    plan_id: `phase2-${digest(JSON.stringify(body)).slice(0, 16)}`,
  };
}

function parseArguments(argv) {
  const options = {
    seed: process.env.BONVOYAGE_PHASE2_SEED ?? 'bonvoyage-phase2-baseline-v1',
    repetitions: 5,
    resilienceRepetitions: 3,
    output: '-',
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === '--seed' && value) {
      options.seed = value;
      index += 1;
    } else if (argument === '--repetitions' && value) {
      options.repetitions = Number.parseInt(value, 10);
      index += 1;
    } else if (argument === '--resilience-repetitions' && value) {
      options.resilienceRepetitions = Number.parseInt(value, 10);
      index += 1;
    } else if (argument === '--output' && value) {
      options.output = value;
      index += 1;
    } else {
      throw new Error(`unknown or incomplete argument: ${argument}`);
    }
  }
  return options;
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const serialized = `${JSON.stringify(buildPlan(options), null, 2)}\n`;
  if (options.output === '-') {
    process.stdout.write(serialized);
  } else {
    fs.writeFileSync(options.output, serialized, {flag: 'wx'});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase2-plan: ${error.message}\n`);
    process.exitCode = 1;
  }
}
