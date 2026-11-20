// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

function distribution(values) {
  if (!values.length) return { count: 0 };
  values.sort((a, b) => a - b);
  const percentile = p => values[Math.ceil(p * values.length) - 1];
  return { count: values.length, p50Ms: percentile(0.5), p95Ms: percentile(0.95), maxMs: values.at(-1) };
}

// One file represents one template, cache condition and concurrency level.
// All timestamps for a sample come from the same DSH process and clock.
export function summarize({ templateId, cache, concurrency, prewarmedCapacity, samples }) {
  assert(typeof templateId === 'string' && templateId.trim(), 'Missing template ID');
  assert(['cold', 'warm', 'unknown'].includes(cache), 'Invalid template cache condition');
  assert(Number.isSafeInteger(concurrency) && concurrency > 0, 'Invalid concurrency');
  assert(prewarmedCapacity === null || Number.isSafeInteger(prewarmedCapacity) && prewarmedCapacity >= 0, 'Invalid prewarmed capacity');
  assert(Array.isArray(samples) && samples.length >= concurrency, 'Expected one sample per attempted session');
  const seen = new Set(), ready = [], success = [];
  for (const { session, startMs, readyMs, successMs, outcome } of samples) {
    assert(typeof session === 'string' && session.trim() && !seen.has(session), 'Missing or duplicate session');
    seen.add(session);
    assert(Number.isFinite(startMs) && startMs >= 0, 'Missing first-tool timestamp');
    assert(outcome === 'passed' || outcome === 'failed', 'Missing terminal outcome');
    if (readyMs != null) {
      assert(Number.isFinite(readyMs) && readyMs >= startMs, 'Invalid readiness timestamp');
      ready.push(readyMs - startMs);
    }
    if (outcome === 'failed') {
      assert(successMs == null, 'A failed sample cannot report success');
      continue;
    }
    assert(Number.isFinite(readyMs) && Number.isFinite(successMs) && successMs >= readyMs, 'Incomplete or unordered successful sample');
    success.push(successMs - startMs);
  }
  return { templateId, cache, concurrency, prewarmedCapacity, attempted: samples.length, failed: samples.length - success.length,
    firstToolToReady: distribution(ready), firstToolToSuccess: distribution(success) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    assert(process.argv.length === 3);
    console.log(JSON.stringify(summarize(JSON.parse(await readFile(process.argv[2], 'utf8'))), null, 2));
  } catch {
    console.error('Expected one JSON file with valid, ordered startup samples. See the native Web guide.');
    process.exitCode = 1;
  }
}
