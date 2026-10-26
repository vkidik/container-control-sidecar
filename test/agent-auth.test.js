import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { AgentAuthenticator, approvalRequestPayload, signaturePayload } from '../src/control-plane/agent-auth.js';

test('agent signature validates once and nonce replay is rejected', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const agent = { id: 'edge-1', publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), revokedAt: null };
  const timestamp = 10_000;
  const nonce = randomBytes(32).toString('base64url');
  const path = '/agent/connect';
  const signature = sign(null, Buffer.from(signaturePayload({ agentId: agent.id, timestamp, nonce, path })), privateKey).toString('base64url');
  const request = { headers: { 'x-agent-id': agent.id, 'x-agent-timestamp': String(timestamp), 'x-agent-nonce': nonce, 'x-agent-signature': signature } };
  const auth = new AgentAuthenticator({ store: { getAgent: async () => agent }, now: () => timestamp });
  assert.equal((await auth.authenticate(request, path)).id, agent.id);
  await assert.rejects(() => auth.authenticate(request, path), /replay/);
});

test('agent signature is bound to its exact path and clock window', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const agent = { id: 'edge', publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), revokedAt: null };
  const timestamp = 1_000;
  const nonce = randomBytes(32).toString('base64url');
  const signature = sign(null, Buffer.from(signaturePayload({ agentId: agent.id, timestamp, nonce, path: '/wrong' })), privateKey).toString('base64url');
  const request = { headers: { 'x-agent-id': agent.id, 'x-agent-timestamp': String(timestamp), 'x-agent-nonce': nonce, 'x-agent-signature': signature } };
  const auth = new AgentAuthenticator({ store: { getAgent: async () => agent }, now: () => timestamp });
  await assert.rejects(() => auth.authenticate(request, '/agent/connect'), /signature/);
  const stale = new AgentAuthenticator({ store: { getAgent: async () => agent }, now: () => 100_000 });
  await assert.rejects(() => stale.authenticate(request, '/agent/connect'), /clock skew/);
});

test('approval request proof is bound to the generated key and exact allowlist', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const agentId = 'project-new';
  const timestamp = 5_000;
  const nonce = randomBytes(32).toString('base64url');
  const path = '/agent/enroll';
  const requestData = {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    displayName: 'Project new',
    allowedContainers: ['example-web'],
  };
  const signature = sign(null, Buffer.from(approvalRequestPayload({ agentId, timestamp, nonce, path, ...requestData })), privateKey).toString('base64url');
  const request = { headers: { 'x-agent-id': agentId, 'x-agent-timestamp': String(timestamp), 'x-agent-nonce': nonce, 'x-agent-signature': signature } };
  const auth = new AgentAuthenticator({ store: {}, now: () => timestamp });
  assert.equal(auth.authenticateApprovalRequest(request, path, requestData), agentId);
  assert.throws(() => auth.authenticateApprovalRequest({ headers: { ...request.headers, 'x-agent-nonce': randomBytes(32).toString('base64url') } }, path, {
    ...requestData,
    allowedContainers: ['other'],
  }), /signature/);
});
