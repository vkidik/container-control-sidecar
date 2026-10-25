import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { OperationExecutor, OperationLedger } from '../src/agent/operation-ledger.js';

async function ledger() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-ledger-'));
  const instance = new OperationLedger(path.join(directory, 'operations.json'));
  await instance.init();
  return instance;
}

test('same command ID is executed once and returns the durable prior result', async () => {
  const state = await ledger();
  let calls = 0;
  const executor = new OperationExecutor({ ledger: state, execute: async () => ({ outcome: 'success', calls: ++calls }) });
  const command = { commandId: '12345678901234567890', container: 'api', action: 'restart' };
  assert.deepEqual(await executor.run(command), { outcome: 'success', calls: 1 });
  assert.deepEqual(await executor.run(command), { outcome: 'success', calls: 1, replayed: true });
  assert.equal(calls, 1);
});

test('conflicting mutation on one container is rejected while first is active', async () => {
  const state = await ledger();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const executor = new OperationExecutor({ ledger: state, execute: async () => { await gate; return { outcome: 'success' }; } });
  const first = executor.run({ commandId: 'aaaaaaaaaaaaaaaaaaaa', container: 'api', action: 'restart' });
  await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(() => executor.run({ commandId: 'bbbbbbbbbbbbbbbbbbbb', container: 'api', action: 'stop' }), (error) => error.code === 'CONFLICT');
  release();
  await first;
});

test('indeterminate command is not automatically repeated', async () => {
  const state = await ledger();
  const error = new Error('socket closed');
  error.indeterminate = true;
  const executor = new OperationExecutor({ ledger: state, execute: async () => { throw error; } });
  const command = { commandId: 'cccccccccccccccccccc', container: 'api', action: 'restart' };
  await assert.rejects(() => executor.run(command), (caught) => caught.code === 'INDETERMINATE');
  await assert.rejects(() => executor.run(command), (caught) => caught.code === 'INDETERMINATE');
});
