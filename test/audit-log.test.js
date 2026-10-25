import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFile, mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { AuditLog } from '../src/control-plane/audit-log.js';

test('audit entries form a verified append-only hash chain', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-audit-'));
  const file = path.join(directory, 'audit.jsonl');
  const audit = new AuditLog(file);
  await audit.init();
  const first = await audit.append({ actor: 'owner', event: 'one', outcome: 'success' });
  const second = await audit.append({ actor: 'owner', event: 'two', outcome: 'success' });
  assert.equal(second.previousHash, first.hash);
  const reopened = new AuditLog(file);
  await reopened.init();
  await appendFile(file, '{"tampered":true}\n');
  await assert.rejects(() => new AuditLog(file).init(), /verification failed|previousHash/);
});
