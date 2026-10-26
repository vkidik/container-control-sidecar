import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { agentWebSocketUrl, loadAgentConfig, parseControlPlaneUrl } from '../src/agent/config.js';
import { loadOrCreateIdentity } from '../src/agent/identity.js';

test('remote control-plane addresses require TLS', () => {
  assert.equal(parseControlPlaneUrl('https://control.tailnet.ts.net').href, 'https://control.tailnet.ts.net/');
  assert.throws(() => parseControlPlaneUrl('http://control.tailnet.ts.net'), /http is allowed only/);
  assert.throws(() => parseControlPlaneUrl('https://user:pass@control.tailnet.ts.net'), /credentials/);
});

test('same-host loopback supports HTTP and matching insecure WebSocket', () => {
  for (const value of ['http://localhost:8787', 'http://127.0.0.1:8787', 'http://127.42.0.9:8787', 'http://[::1]:8787']) {
    const url = parseControlPlaneUrl(value);
    assert.equal(agentWebSocketUrl(url).protocol, 'ws:');
  }
  assert.equal(agentWebSocketUrl(parseControlPlaneUrl('https://control.tailnet.ts.net')).protocol, 'wss:');
});

test('agent uses the current container hostname after Docker recreates it', () => {
  const config = loadAgentConfig({
    CONTROL_PLANE_URL: 'https://control.example',
    HOSTNAME: 'deleted-container-id',
  }, () => 'current-container-id');

  assert.equal(config.containerId, 'current-container-id');
});

test('agent endpoint, identity, and token may come from image environment or mounted files', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-agent-config-'));
  const agentIdFile = path.join(directory, 'agent-id');
  const urlFile = path.join(directory, 'control-plane-url');
  const tokenFile = path.join(directory, 'enrollment-token');
  await Promise.all([
    writeFile(agentIdFile, 'project-server-7\n'),
    writeFile(urlFile, 'https://control.example\n'),
    writeFile(tokenFile, 'one-time-token\n'),
  ]);
  const config = loadAgentConfig({
    AGENT_ID_FILE: agentIdFile,
    CONTROL_PLANE_URL_FILE: urlFile,
    ENROLLMENT_TOKEN_FILE: tokenFile,
    HOSTNAME: 'agent-container-id',
  });
  assert.equal(config.serverId, 'project-server-7');
  assert.equal(config.controlPlaneUrl.href, 'https://control.example/');
  assert.equal(config.enrollmentToken, 'one-time-token');
  assert.throws(() => loadAgentConfig({
    CONTROL_PLANE_URL: 'https://control.example',
    CONTROL_PLANE_URL_FILE: urlFile,
    HOSTNAME: 'agent-container-id',
  }), /mutually exclusive/);
  assert.throws(() => loadAgentConfig({
    AGENT_ID: 'server-a',
    AGENT_ID_FILE: agentIdFile,
    CONTROL_PLANE_URL: 'https://control.example',
    HOSTNAME: 'agent-container-id',
  }), /mutually exclusive/);
});

test('agent can generate and persist a stable id when AGENT_ID is omitted', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-auto-id-'));
  const config = loadAgentConfig({
    CONTROL_PLANE_URL: 'https://control.example',
    ENROLLMENT_TOKEN: 'fleet-token',
    HOSTNAME: 'agent-container-id',
    AGENT_DATA_DIR: directory,
  });
  assert.equal(config.serverId, null);
  const first = await loadOrCreateIdentity(config.identityFile, config.serverId);
  const second = await loadOrCreateIdentity(config.identityFile, config.serverId);
  assert.match(first.serverId, /^agent-[a-f0-9]{20}$/);
  assert.equal(second.serverId, first.serverId);
});
