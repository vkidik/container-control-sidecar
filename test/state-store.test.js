import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { StateStore } from '../src/control-plane/state-store.js';

async function store() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-state-'));
  const instance = new StateStore(path.join(directory, 'state.json'), { username: 'owner', displayName: 'Owner' });
  await instance.init();
  return instance;
}

test('enrollment token is server-scoped, allowlist-scoped, expiring, and one-time', async () => {
  const state = await store();
  const enrollment = await state.issueEnrollment({ serverId: 'edge-1', displayName: 'Edge', allowedContainers: ['api', 'web'], ttlMs: 1000, now: 1000 });
  await assert.rejects(() => state.consumeEnrollment({ token: enrollment.token, serverId: 'edge-2', publicKey: 'key', allowedContainers: ['api', 'web'], now: 1100 }), /invalid/);
  await assert.rejects(() => state.consumeEnrollment({ token: enrollment.token, serverId: 'edge-1', publicKey: 'key', allowedContainers: ['api'], now: 1100 }), /allowlist/);
  const agent = await state.consumeEnrollment({ token: enrollment.token, serverId: 'edge-1', publicKey: 'key', allowedContainers: ['web', 'api'], now: 1100 });
  assert.deepEqual(agent.allowedContainers, ['api', 'web']);
  const retried = await state.consumeEnrollment({ token: enrollment.token, serverId: 'edge-1', publicKey: 'key', allowedContainers: ['api', 'web'], now: 1200 });
  assert.equal(retried.id, agent.id);
  await assert.rejects(() => state.consumeEnrollment({ token: enrollment.token, serverId: 'edge-1', publicKey: 'different-key', allowedContainers: ['api', 'web'], now: 1200 }), /already used/);
});

test('expired enrollment and active agent replacement are rejected', async () => {
  const state = await store();
  const expired = await state.issueEnrollment({ serverId: 'edge', allowedContainers: ['api'], ttlMs: 10, now: 1000 });
  await assert.rejects(() => state.consumeEnrollment({ token: expired.token, serverId: 'edge', publicKey: 'key', allowedContainers: ['api'], now: 1011 }), /expired/);
  const active = await state.issueEnrollment({ serverId: 'other', allowedContainers: ['api'], ttlMs: 1000, now: 1000 });
  await state.consumeEnrollment({ token: active.token, serverId: 'other', publicKey: 'key', allowedContainers: ['api'], now: 1001 });
  await assert.rejects(() => state.issueEnrollment({ serverId: 'other', allowedContainers: ['api'], ttlMs: 1000 }), /already exists/);
});

test('fleet enrollment accepts independently generated ids up to its bounded use count', async () => {
  const state = await store();
  const enrollment = await state.issueFleetEnrollment({
    idPrefix: 'project', displayNamePrefix: 'Project', allowedContainers: ['example-web'],
    ttlMs: 1000, maxUses: 2, now: 1000,
  });
  await assert.rejects(() => state.consumeEnrollment({
    token: enrollment.token, serverId: 'other-a', publicKey: 'key-a',
    allowedContainers: ['example-web'], now: 1100,
  }), /prefix/);
  const first = await state.consumeEnrollment({
    token: enrollment.token, serverId: 'project-a', publicKey: 'key-a',
    allowedContainers: ['example-web'], now: 1100,
  });
  assert.equal(first.displayName, 'Project a');
  const retried = await state.consumeEnrollment({
    token: enrollment.token, serverId: 'project-a', publicKey: 'key-a',
    allowedContainers: ['example-web'], now: 1150,
  });
  assert.equal(retried.id, first.id);
  await state.consumeEnrollment({
    token: enrollment.token, serverId: 'project-b', publicKey: 'key-b',
    allowedContainers: ['example-web'], now: 1200,
  });
  await assert.rejects(() => state.consumeEnrollment({
    token: enrollment.token, serverId: 'project-c', publicKey: 'key-c',
    allowedContainers: ['example-web'], now: 1250,
  }), /exhausted/);
});

test('fleet enrollment remains allowlist scoped and expires', async () => {
  const state = await store();
  const enrollment = await state.issueFleetEnrollment({
    idPrefix: 'project', allowedContainers: ['example-web'], ttlMs: 10, maxUses: 3, now: 1000,
  });
  await assert.rejects(() => state.consumeEnrollment({
    token: enrollment.token, serverId: 'project-a', publicKey: 'key-a', allowedContainers: ['other'], now: 1005,
  }), /allowlist/);
  await assert.rejects(() => state.consumeEnrollment({
    token: enrollment.token, serverId: 'project-a', publicKey: 'key-a', allowedContainers: ['example-web'], now: 1011,
  }), /expired/);
});

test('approval request remains pending until the owner approves its exact key', async () => {
  const state = await store();
  const requested = await state.requestAgentApproval({
    serverId: 'project-new',
    displayName: 'Project new server',
    publicKey: 'key-a',
    allowedContainers: ['example-web'],
    now: 1000,
  });
  assert.equal(requested.status, 'pending');
  assert.equal(requested.created, true);
  assert.equal(await state.getAgent('project-new'), null);
  assert.equal((await state.listPendingAgents()).length, 1);

  const repeated = await state.requestAgentApproval({
    serverId: 'project-new',
    displayName: 'Changed name is ignored',
    publicKey: 'key-a',
    allowedContainers: ['example-web'],
    now: 1100,
  });
  assert.equal(repeated.created, false);
  await assert.rejects(() => state.requestAgentApproval({
    serverId: 'project-new',
    publicKey: 'key-b',
    allowedContainers: ['example-web'],
  }), /different key or allowlist/);

  const approved = await state.approveAgentRequest('project-new', 1200);
  assert.equal(approved.publicKey, 'key-a');
  assert.deepEqual(approved.allowedContainers, ['example-web']);
  assert.equal((await state.listPendingAgents()).length, 0);
  const afterApproval = await state.requestAgentApproval({
    serverId: 'project-new',
    publicKey: 'key-a',
    allowedContainers: ['example-web'],
    now: 1300,
  });
  assert.equal(afterApproval.status, 'approved');
});

test('folders organize agents and deleting a folder safely ungroups them', async () => {
  const state = await store();
  const enrollment = await state.issueEnrollment({ serverId: 'edge-folder', allowedContainers: ['api'], ttlMs: 1000, now: 1000 });
  await state.consumeEnrollment({
    token: enrollment.token, serverId: 'edge-folder', publicKey: 'key', allowedContainers: ['api'], now: 1100,
  });

  const production = await state.createFolder('Production', 1200);
  const staging = await state.createFolder('Staging', 1200);
  await assert.rejects(() => state.createFolder('production'), /already exists/);
  const moved = await state.moveAgentToFolder('edge-folder', production.id);
  assert.equal(moved.folderId, production.id);
  assert.equal((await state.getAgent('edge-folder')).folderId, production.id);

  const renamed = await state.renameFolder(staging.id, 'QA', 1300);
  assert.equal(renamed.name, 'QA');
  assert.deepEqual((await state.listFolders()).map((folder) => folder.name), ['Production', 'QA']);

  const deleted = await state.deleteFolder(production.id);
  assert.equal(deleted.movedAgents, 1);
  assert.equal((await state.getAgent('edge-folder')).folderId, null);
});
