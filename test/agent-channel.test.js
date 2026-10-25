import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';
import { createControlPlane } from '../src/control-plane/app.js';
import { signaturePayload } from '../src/control-plane/agent-auth.js';

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
