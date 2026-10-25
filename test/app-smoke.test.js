import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createControlPlane } from '../src/control-plane/app.js';

test('control plane serves UI on loopback but keeps API authenticated', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-app-'));
  const config = {
    dataDir: directory,
    stateFile: path.join(directory, 'state.json'),
    auditFile: path.join(directory, 'audit.jsonl'),
    publicDir: path.resolve('src/control-plane/public'),
    listenHost: '127.0.0.1',
    listenPort: 0,
    privateNetworkMode: 'loopback-proxy',
    rpName: 'Test', rpId: 'test.example.ts.net', origin: 'https://test.example.ts.net',
    ownerUsername: 'owner', ownerDisplayName: 'Owner', bootstrapToken: 'secret',
    sessionIdleMs: 1000, sessionAbsoluteMs: 2000, ceremonyTtlMs: 1000, confirmationTtlMs: 1000, agentRequestTimeoutMs: 1000,
  };
  const { server, agentServer } = await createControlPlane(config);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  await new Promise((resolve) => agentServer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  t.after(() => new Promise((resolve) => agentServer.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const page = await fetch(`${base}/`);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Управление контейнерами/);
  assert.match(html, /Папки проектов/);
  const api = await fetch(`${base}/api/servers`);
  assert.equal(api.status, 401);
  const gateway = `http://127.0.0.1:${agentServer.address().port}`;
  const hiddenPanel = await fetch(`${gateway}/`);
  assert.equal(hiddenPanel.status, 404);
  const hiddenAuth = await fetch(`${gateway}/api/auth/session`);
  assert.equal(hiddenAuth.status, 404);
  const gatewayHealth = await fetch(`${gateway}/healthz`);
  assert.equal(gatewayHealth.status, 200);
});

test('authenticated folder API creates a folder and moves one agent into it', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-folders-'));
  const config = {
    dataDir: directory,
    stateFile: path.join(directory, 'state.json'), auditFile: path.join(directory, 'audit.jsonl'),
    publicDir: path.resolve('src/control-plane/public'), listenHost: '127.0.0.1', listenPort: 0,
    privateNetworkMode: 'loopback-proxy', rpName: 'Test', rpId: 'test.example', origin: 'https://test.example',
    ownerUsername: 'owner', ownerDisplayName: 'Owner', bootstrapToken: 'secret',
    sessionIdleMs: 1000, sessionAbsoluteMs: 2000, ceremonyTtlMs: 1000, confirmationTtlMs: 1000, agentRequestTimeoutMs: 1000,
  };
  const control = await createControlPlane(config);
  await new Promise((resolve) => control.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => control.server.close(resolve)));
  const base = `http://127.0.0.1:${control.server.address().port}`;
  const session = control.sessions.create();
  const headers = { Cookie: `acp_session=${session.id}`, 'X-CSRF-Token': session.csrf, 'Content-Type': 'application/json' };

  const enrollment = await control.store.issueEnrollment({ serverId: 'edge-folder', allowedContainers: ['api'], ttlMs: 10_000 });
  await control.store.consumeEnrollment({ token: enrollment.token, serverId: 'edge-folder', publicKey: 'key', allowedContainers: ['api'] });
  const createdResponse = await fetch(`${base}/api/folders`, { method: 'POST', headers, body: JSON.stringify({ name: 'Project A' }) });
  assert.equal(createdResponse.status, 201);
  const { folder } = await createdResponse.json();
  const movedResponse = await fetch(`${base}/api/servers/edge-folder/folder`, {
    method: 'PATCH', headers, body: JSON.stringify({ folderId: folder.id }),
  });
  assert.equal(movedResponse.status, 200);
  assert.equal((await movedResponse.json()).server.folderId, folder.id);

  const serversResponse = await fetch(`${base}/api/servers`, { headers: { Cookie: `acp_session=${session.id}` } });
  assert.equal((await serversResponse.json()).servers[0].folderId, folder.id);
});
