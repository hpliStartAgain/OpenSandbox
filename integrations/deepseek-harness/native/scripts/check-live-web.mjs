// Copyright 2026 The OpenSandbox Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { Sandbox, SandboxApiException, SandboxManager } from '@alibaba-group/opensandbox';

class CheckError extends Error {}
function requireCheck(ok, message) {
  if (!ok) throw new CheckError(message);
}

async function withSandbox(connect, id, operation) {
  const box = await connect(id);
  try {
    return await operation(box);
  } finally {
    await box.close();
  }
}

async function expectOutput(box, argv, cwd, expected) {
  const result = await box.commands.run(argv, { workingDirectory: cwd, timeoutSeconds: 5 });
  requireCheck(result.exitCode === 0 && !result.error && result.logs.stdout.length === 1 &&
    result.logs.stdout[0].text.replace(/\r?\n$/, '') === expected, 'Unexpected argv result. Check execd, workspace and probe output.');
}

// Read one extra byte so a longer file with a matching prefix cannot pass.
async function expectBytes(box, path, text) {
  const expected = Buffer.from(text);
  const actual = Buffer.from(await box.files.readBytes(path, { range: `bytes=0-${expected.length}` }));
  requireCheck(actual.equals(expected), 'Remote file content did not match the expected bytes.');
  return createHash('sha256').update(actual).digest('hex');
}

export async function runCheck(args, { connect, manager, cwd, report, cleanupMs = 180_000, pollMs = 1000 }) {
  const [stage, run, first, second] = args;
  if (stage === 'preflight') {
    requireCheck(args.length === 2 && run, 'Usage: preflight PROBE_SANDBOX_ID');
    const marker = 'dsh argv probe';
    await withSandbox(connect, run, box => expectOutput(box, ['printf', '%s', marker], cwd, marker));
    report({ stage, argv: 'passed' });
    return;
  }

  requireCheck(/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(run ?? ''), 'Use one fresh UUID per run.');
  requireCheck(first && ((stage === 'seed' && args.length === 3) ||
    (stage === 'verify' && args.length === 4 && second && first !== second)), 'Usage: seed RUN A, or verify RUN A B with distinct IDs.');
  const prefix = `${cwd.replace(/\/$/, '')}/dsh-${run}`;
  const input = `input ${run}\n`;
  if (stage === 'seed') {
    await withSandbox(connect, first, async box => {
      await expectBytes(box, prefix + '.a', `A ${run}\n`);
      await box.files.writeFiles([{ path: prefix + '.in', data: input, mode: 600 }]);
      await expectBytes(box, prefix + '.in', input);
    });
    report({ stage, input: 'uploaded and read back' });
    return;
  }

  const sha256 = await withSandbox(connect, first, async box => {
    await expectBytes(box, prefix + '.a', `A ${run}\n`);
    return expectBytes(box, prefix + '.out', input.toUpperCase());
  });
  await withSandbox(connect, second, async box => {
    await expectBytes(box, prefix + '.b', `B ${run}\n`);
    // Only ENOENT counts as absence. Permission failures must fail the check.
    const check = 'import os, sys\nfor path in sys.argv[1:]:\n try: os.lstat(path)\n except FileNotFoundError: continue\n sys.exit(1)\nprint("isolated")';
    await expectOutput(box, ['python3', '-c', check, prefix + '.a', prefix + '.in', prefix + '.out'], cwd, 'isolated');
  });
  report({ stage: 'artifacts-and-isolation', sha256, next: 'Explicitly delete A and B from their DSH Web sessions now.' });

  const pending = new Set([first, second]);
  const deadline = performance.now() + cleanupMs;
  while (pending.size && performance.now() < deadline) {
    for (const id of pending) {
      try {
        await manager.getSandboxInfo(id);
      } catch (error) {
        if (!(error instanceof SandboxApiException && error.statusCode === 404)) throw error;
        pending.delete(id);
      }
    }
    if (pending.size) await delay(pollMs);
  }
  requireCheck(!pending.size, 'Cleanup unconfirmed. Inspect the recorded sandbox IDs on the target deployment.');
  report({ stage: 'cleanup', confirmed404: 2 });
}

async function main(args) {
  if (args.length === 1 && args[0] === 'new-run') return console.log(randomUUID());
  const { validateNativeConfig } = await import('../dist/config.js');
  const config = validateNativeConfig({
    protocol: process.env.OPENSANDBOX_PROTOCOL ?? 'https', domain: process.env.OPENSANDBOX_DOMAIN,
    apiKey: process.env.OPENSANDBOX_API_KEY, kind: 'create-template', templateId: process.env.OPENSANDBOX_TEMPLATE_ID,
    remoteCwd: process.env.DSH_REMOTE_CWD ?? '/tmp',
  });
  const connectionConfig = { domain: config.domain, protocol: config.protocol, apiKey: config.apiKey,
    requestTimeoutSeconds: 15, disableMetrics: true };
  const manager = SandboxManager.create({ connectionConfig });
  try {
    await runCheck(args, { manager, cwd: config.remoteCwd,
      connect: sandboxId => Sandbox.connect({ sandboxId, connectionConfig, readyTimeoutSeconds: 30 }),
      report: value => console.log(JSON.stringify(value)),
    });
  } finally {
    await manager.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => {
    const status = error instanceof SandboxApiException ? ` HTTP ${error.statusCode}` : '';
    console.error(error instanceof CheckError ? error.message : `Live Web check failed.${status} Check configuration, Ingress and sandbox state.`);
    process.exitCode = 1;
  });
}
