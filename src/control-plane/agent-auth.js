import { createPublicKey, verify } from 'node:crypto';
import { assertIdentifier } from '../shared/validation.js';

export function signaturePayload({ agentId, timestamp, nonce, path }) {
  return `${agentId}\n${timestamp}\n${nonce}\n${path}`;
}

export function approvalRequestPayload({ agentId, timestamp, nonce, path, publicKey, displayName, allowedContainers }) {
  return `${signaturePayload({ agentId, timestamp, nonce, path })}\n${publicKey}\n${displayName}\n${allowedContainers.join(',')}`;
}

export class AgentAuthenticator {
  constructor({ store, maxClockSkewMs = 30_000, nonceTtlMs = 120_000, now = () => Date.now() }) {
    this.store = store;
    this.maxClockSkewMs = maxClockSkewMs;
    this.nonceTtlMs = nonceTtlMs;
    this.now = now;
    this.nonces = new Map();
  }

  async authenticate(request, path) {
    const agentId = assertIdentifier(request.headers['x-agent-id'], 'x-agent-id');
    const timestamp = Number(request.headers['x-agent-timestamp']);
    const nonce = String(request.headers['x-agent-nonce'] || '');
    const signature = String(request.headers['x-agent-signature'] || '');
    if (!Number.isSafeInteger(timestamp) || Math.abs(this.now() - timestamp) > this.maxClockSkewMs) {
      throw new Error('agent timestamp outside allowed clock skew');
    }
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(nonce)) throw new Error('invalid agent nonce');
    this.#prune();
    const replayKey = `${agentId}:${nonce}`;
    if (this.nonces.has(replayKey)) throw new Error('agent authentication replay detected');
    const agent = await this.store.getAgent(agentId);
    if (!agent || agent.revokedAt) throw new Error('agent not enrolled or revoked');
    const ok = verify(
      null,
      Buffer.from(signaturePayload({ agentId, timestamp, nonce, path })),
      createPublicKey({ key: Buffer.from(agent.publicKey, 'base64'), type: 'spki', format: 'der' }),
      Buffer.from(signature, 'base64url'),
    );
    if (!ok) throw new Error('invalid agent signature');
    this.nonces.set(replayKey, this.now() + this.nonceTtlMs);
    return agent;
  }

  authenticateApprovalRequest(request, path, { publicKey, displayName, allowedContainers }) {
    const agentId = assertIdentifier(request.headers['x-agent-id'], 'x-agent-id');
    const timestamp = Number(request.headers['x-agent-timestamp']);
    const nonce = String(request.headers['x-agent-nonce'] || '');
    const signature = String(request.headers['x-agent-signature'] || '');
    if (!Number.isSafeInteger(timestamp) || Math.abs(this.now() - timestamp) > this.maxClockSkewMs) {
      throw new Error('agent timestamp outside allowed clock skew');
    }
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(nonce)) throw new Error('invalid agent nonce');
    this.#prune();
    const replayKey = `${agentId}:${nonce}`;
    if (this.nonces.has(replayKey)) throw new Error('agent authentication replay detected');
    const ok = verify(
      null,
      Buffer.from(approvalRequestPayload({ agentId, timestamp, nonce, path, publicKey, displayName, allowedContainers })),
      createPublicKey({ key: Buffer.from(publicKey, 'base64'), type: 'spki', format: 'der' }),
      Buffer.from(signature, 'base64url'),
    );
    if (!ok) throw new Error('invalid agent signature');
    this.nonces.set(replayKey, this.now() + this.nonceTtlMs);
    return agentId;
  }

  #prune() {
    const timestamp = this.now();
    for (const [key, expiresAt] of this.nonces) if (expiresAt < timestamp) this.nonces.delete(key);
  }
}
