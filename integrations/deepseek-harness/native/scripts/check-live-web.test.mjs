// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { SandboxApiException } from '@alibaba-group/opensandbox';
import { runCheck } from './check-live-web.mjs';
import { summarize } from './summarize-web-startup.mjs';

const run = '12345678-1234-4234-8234-123456789abc';
const prefix = `dsh-${run}`;
const cwd = '/tmp';
const exec = promisify(execFile);
const apiError = statusCode => new SandboxApiException({ statusCode, message: 'test' });

async function fixture(t) {
  const roots = {};
  const reports = [], closed = [], lookup = [];
  for (const id of ['A', 'B']) {
    roots[id] = await mkdtemp(join(tmpdir(), 'check-live-web-'));
    t.after(() => rm(roots[id], { recursive: true, force: true }));
  }
  const context = {
    cwd, pollMs: 1, cleanupMs: 3000, report: value => reports.push(value),
    manager: { async getSandboxInfo(id) {
      lookup.push(id);
      if (lookup.filter(value => value === id).length > 1) throw apiError(404);
      return { id };
    } },
    async connect(id) {
      const local = path => path.replace(/^\/tmp\//, roots[id] + '/');
      return {
        files: {
          readBytes: path => readFile(local(path)),
          writeFiles: async ([entry]) => writeFile(local(entry.path), entry.data),
        },
        commands: { async run([program, ...args], options) {
          assert.equal(options.workingDirectory, cwd);
          const { stdout } = await exec(program, args.map(local), { cwd: roots[id] });
          return { exitCode: 0, logs: { stdout: [{ text: stdout }] } };
        } },
        close: async () => closed.push(id),
      };
    },
  };
  const put = (id, suffix, value) => writeFile(join(roots[id], prefix + suffix), value);
  await put('A', '.a', `A ${run}\n`);
  await put('B', '.b', `B ${run}\n`);
  await put('A', '.out', `INPUT ${run.toUpperCase()}\n`);
  return { context, put, closed, reports, lookup };
}

test('argv, file-first seed, independent two-session reads and eventual 404', async t => {
  const {context, reports, closed, lookup} = await fixture(t);
  await runCheck(['preflight', 'A'], context);
  await runCheck(['seed', run, 'A'], context);
  await runCheck(['verify', run, 'A', 'B'], context);
  assert.deepEqual(closed, ['A', 'A', 'A', 'B']);
  assert.deepEqual(lookup, ['A', 'B', 'A', 'B']);
  assert.deepEqual(reports.map(x => x.stage), ['preflight', 'seed', 'artifacts-and-isolation', 'cleanup']);
});

test('wrong IDs, extra artifact bytes and cross-session leakage fail before cleanup', async t => {
  const {context, put, lookup} = await fixture(t);
  await assert.rejects(runCheck(['verify', run, 'A', 'A'], context), /distinct IDs/);
  await put('A', '.out', `INPUT ${run.toUpperCase()}\nx`);
  await assert.rejects(runCheck(['verify', run, 'A', 'B'], context), /bytes/);
  await put('A', '.out', `INPUT ${run.toUpperCase()}\n`);
  await put('B', '.in', 'unexpected');
  await assert.rejects(runCheck(['verify', run, 'A', 'B'], context));
  assert.deepEqual(lookup, []);
});

test('permission failure or a sandbox still present does not confirm deletion', async t => {
  const {context, reports} = await fixture(t);
  context.manager.getSandboxInfo = async () => { throw apiError(403); };
  await assert.rejects(runCheck(['verify', run, 'A', 'B'], context), { statusCode: 403 });
  context.manager.getSandboxInfo = async () => ({});
  context.cleanupMs = 5;
  await assert.rejects(runCheck(['verify', run, 'A', 'B'], context), /Cleanup unconfirmed/);
  assert(!reports.some(x => x.stage === 'cleanup'));
});

test('startup summaries preserve partial readiness, failed samples and percentile denominators', () => {
  const samples = [
    {session: '1', startMs: 5, readyMs: 10, successMs: 25, outcome: 'passed'},
    {session: '2', startMs: 6, readyMs: 16, outcome: 'failed'},
    {session: '3', startMs: 7, outcome: 'failed'},
  ];
  const group = {templateId: 'fixture', cache: 'unknown', concurrency: 2, prewarmedCapacity: null, samples};
  const report = summarize(group);
  assert.equal(report.attempted, 3);
  assert.equal(report.failed, 2);
  assert.deepEqual(report.firstToolToReady, {count: 2, p50Ms: 5, p95Ms: 10, maxMs: 10});
  assert.deepEqual(report.firstToolToSuccess, {count: 1, p50Ms: 20, p95Ms: 20, maxMs: 20});
  assert.throws(() => summarize({...group, samples: [samples[0], samples[0]]}), /duplicate/);
  assert.throws(() => summarize({...group, samples: [samples[1], {...samples[0], successMs: 9}]}), /unordered/);
  assert.throws(() => summarize({...group, samples: [samples[1], {...samples[2], outcome: 'passed'}]}), /Incomplete/);
});
