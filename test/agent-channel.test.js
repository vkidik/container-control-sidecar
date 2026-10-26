import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';
import { createControlPlane } from '../src/control-plane/app.js';
import { approvalRequestPayload, signaturePayload } from '../src/control-plane/agent-auth.js';

function enrollmentRequest(port, { agentId, privateKey, publicKey, displayName, allowedContainers, enrollmentToken = '' }) {
  const pathName = '/agent/enroll';
  const timestamp = Date.now();
  const nonce = randomBytes(32).toString('base64url');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const signature = sign(null, Buffer.from(approvalRequestPayload({
    agentId,
    timestamp,
    nonce,
    path: pathName,
    publicKey: publicKeyDer,
    displayName,
    allowedContainers,
  })), privateKey).toString('base64url');
  const enrollment = Buffer.from(JSON.stringify({
    publicKey: publicKeyDer,
    displayName,
    allowedContainers,
    enrollmentToken,
  })).toString('base64url');
  const socket = new WebSocket(`ws://127.0.0.1:${port}${pathName}`, {
    headers: {
      'X-Agent-Id': agentId,
      'X-Agent-Timestamp': String(timestamp),
      'X-Agent-Nonce': nonce,
      'X-Agent-Signature': signature,
      'X-Agent-Enrollment': enrollment,
    },
  });
  return new Promise((resolve, reject) => {
    let result;
    socket.once('message', (data) => { result = JSON.parse(data.toString('utf8')); });
    socket.once('error', reject);
    socket.once('close', () => result ? resolve(result) : reject(new Error('enrollment socket closed without a response')));
  });
}

test('new agent requests and completes owner approval entirely over WebSocket', { timeout: 5000 }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-channel-enroll-'));
  const config = {
    dataDir: directory,
    stateFile: path.join(directory, 'state.json'), auditFile: path.join(directory, 'audit.jsonl'),
    publicDir: path.resolve('src/control-plane/public'), listenHost: '127.0.0.1', listenPort: 0,
    privateNetworkMode: 'loopback-proxy', rpName: 'Test', rpId: 'test.example.ts.net', origin: 'https://test.example.ts.net',
    ownerUsername: 'owner', ownerDisplayName: 'Owner', bootstrapToken: 'secret',
    sessionIdleMs: 1000, sessionAbsoluteMs: 2000, ceremonyTtlMs: 1000, confirmationTtlMs: 1000, agentRequestTimeoutMs: 1000,
    approvalEnrollmentEnabled: true,
  };
  const control = await createControlPlane(config);
  await new Promise((resolve) => control.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => control.server.close(resolve)));

  const keys = generateKeyPairSync('ed25519');
  const request = {
    agentId: 'edge-pending',
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    displayName: 'Edge pending',
    allowedContainers: ['api'],
  };
  const pending = await enrollmentRequest(control.server.address().port, request);
  assert.deepEqual(pending, { type: 'enrollment', status: 'pending', serverId: 'edge-pending' });
  assert.equal((await control.store.listPendingAgents())[0].id, 'edge-pending');

  await control.store.approveAgentRequest('edge-pending');
  const approved = await enrollmentRequest(control.server.address().port, request);
  assert.deepEqual(approved, {
    type: 'enrollment',
    status: 'approved',
    serverId: 'edge-pending',
    allowedContainers: ['api'],
  });
});

test('one-time enrollment token is consumed through WebSocket', { timeout: 5000 }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-channel-token-'));
  const config = {
    dataDir: directory,
    stateFile: path.join(directory, 'state.json'), auditFile: path.join(directory, 'audit.jsonl'),
    publicDir: path.resolve('src/control-plane/public'), listenHost: '127.0.0.1', listenPort: 0,
    privateNetworkMode: 'loopback-proxy', rpName: 'Test', rpId: 'test.example.ts.net', origin: 'https://test.example.ts.net',
    ownerUsername: 'owner', ownerDisplayName: 'Owner', bootstrapToken: 'secret',
    sessionIdleMs: 1000, sessionAbsoluteMs: 2000, ceremonyTtlMs: 1000, confirmationTtlMs: 1000, agentRequestTimeoutMs: 1000,
    approvalEnrollmentEnabled: false,
  };
  const control = await createControlPlane(config);
  await new Promise((resolve) => control.server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => control.server.close(resolve)));

  const enrollment = await control.store.issueEnrollment({ serverId: 'edge-token', allowedContainers: ['api'], ttlMs: 10_000 });
  const keys = generateKeyPairSync('ed25519');
  const approved = await enrollmentRequest(control.server.address().port, {
    agentId: 'edge-token',
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    displayName: 'Edge token',
    allowedContainers: ['api'],
    enrollmentToken: enrollment.token,
  });
  assert.deepEqual(approved, {
    type: 'enrollment',
    status: 'approved',
    serverId: 'edge-token',
    allowedContainers: ['api'],
  });
  assert.equal((await control.store.getAgent('edge-token')).id, 'edge-token');
});

test('enrolled agent opens a signed outbound channel and answers requests', { timeout: 5000 }, async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-channel-'));
  const config = {
    dataDir: directory,
    stateFile: path.join(directory, 'state.json'), auditFile: path.join(directory, 'audit.jsonl'),
    publicDir: path.resolve('src/control-plane/public'), listenHost: '127.0.0.1', listenPort: 0,
    privateNetworkMode: 'loopback-proxy', rpName: 'Test', rpId: 'test.example.ts.net', origin: 'https://test.example.ts.net',
    ownerUsername: 'owner', ownerDisplayName: 'Owner', bootstrapToken: 'secret',
    sessionIdleMs: 1000, sessionAbsoluteMs: 2000, ceremonyTtlMs: 1000, confirmationTtlMs: 1000, agentRequestTimeoutMs: 1000,
  };
  const control = await createControlPlane(config);
  await new Promise((resolve) => control.server.listen(0, '127.0.0.1', resolve));

  const keys = generateKeyPairSync('ed25519');
  const enrollment = await control.store.issueEnrollment({ serverId: 'edge', allowedContainers: ['api'], ttlMs: 1000 });
  await control.store.consumeEnrollment({
    token: enrollment.token, serverId: 'edge', allowedContainers: ['api'],
    publicKey: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  });
  const timestamp = Date.now();
  const nonce = randomBytes(32).toString('base64url');
  const pathName = '/agent/connect';
  const signature = sign(null, Buffer.from(signaturePayload({ agentId: 'edge', timestamp, nonce, path: pathName })), keys.privateKey).toString('base64url');
  const socket = new WebSocket(`ws://127.0.0.1:${control.server.address().port}${pathName}`, {
    headers: { 'X-Agent-Id': 'edge', 'X-Agent-Timestamp': String(timestamp), 'X-Agent-Nonce': nonce, 'X-Agent-Signature': signature },
  });
  t.after(async () => {
    await new Promise((resolve) => {
      if (socket.readyState === WebSocket.CLOSED) return resolve();
      socket.once('close', resolve);
      socket.close();
      setTimeout(() => { socket.terminate(); resolve(); }, 500).unref();
    });
    await new Promise((resolve) => control.server.close(resolve));
  });
  socket.on('message', (data) => {
    const message = JSON.parse(data.toString());
    if (message.type !== 'request') return;
    const result = message.operation === 'logs' ? { container: 'api', logs: 'ok' } : { containers: [] };
    socket.send(JSON.stringify({ type: 'response', requestId: message.requestId, ok: true, result }));
  });
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
  assert.equal(control.hub.isConnected('edge'), true);
  assert.deepEqual(await control.hub.request('edge', 'logs', { container: 'api', tail: 10 }), { container: 'api', logs: 'ok' });
});
