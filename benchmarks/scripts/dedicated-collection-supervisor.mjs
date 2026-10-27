import {performance} from 'node:perf_hooks';
import {setTimeout as delay} from 'node:timers/promises';

export function collectionTimeout(value = '3600', idleSeconds = 0) {
  if (!/^[1-9][0-9]*$/u.test(String(value))) {
    throw new Error('collection timeout must be an integer from 1 to 14400 seconds');
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds > 14400 || seconds <= idleSeconds) {
    throw new Error('collection timeout must exceed observation and be at most 14400 seconds');
  }
  return seconds * 1000;
}

export function createCollectionSupervisor({timeoutMs, emitter = process}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 14400000) {
    throw new Error('invalid collection deadline');
  }
  const controller = new AbortController();
  const startedAt = new Date();
  const started = performance.now();
  const cancel = (kind, message = kind) => {
    if (!controller.signal.aborted) {
      const error = new Error(message);
      error.kind = kind;
      controller.abort(error);
    }
  };
  const onInt = () => cancel('SIGINT', 'collection cancelled by SIGINT');
  const onTerm = () => cancel('SIGTERM', 'collection cancelled by SIGTERM');
  emitter.on('SIGINT', onInt);
  emitter.on('SIGTERM', onTerm);
  const timer = setTimeout(() => cancel('deadline', 'collection deadline exceeded'), timeoutMs);
  const check = () => {
    // Also check monotonic elapsed time after synchronous parsing or hashing.
    if (performance.now() - started >= timeoutMs) cancel('deadline', 'collection deadline exceeded');
    controller.signal.throwIfAborted();
  };
  return {
    signal: controller.signal,
    cancel,
    check,
    async wait(milliseconds) {
      check();
      try {
        await delay(milliseconds, undefined, {signal: controller.signal});
      } catch (error) {
        if (controller.signal.aborted) throw controller.signal.reason;
        throw error;
      }
      check();
    },
    snapshot() {
      return {
        started_at: startedAt.toISOString(),
        deadline_at: new Date(startedAt.getTime() + timeoutMs).toISOString(),
        timeout_ms: timeoutMs,
        elapsed_ms: Math.round(performance.now() - started),
        cancellation_reason: controller.signal.reason?.kind ?? null,
        cancelled: controller.signal.aborted,
      };
    },
    dispose() {
      clearTimeout(timer);
      emitter.removeListener('SIGINT', onInt);
      emitter.removeListener('SIGTERM', onTerm);
    },
  };
}

