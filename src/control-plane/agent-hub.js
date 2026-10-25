import { randomUUID } from 'node:crypto';

export class AgentHub {
  constructor({ requestTimeoutMs = 20_000 } = {}) {
    this.requestTimeoutMs = requestTimeoutMs;
    this.connections = new Map();
    this.pending = new Map();
    this.snapshots = new Map();
  }

  register(agent, socket) {
    const prior = this.connections.get(agent.id);
    if (prior) prior.close(4001, 'replaced by newer connection');
    this.connections.set(agent.id, socket);
    socket.on('message', (data) => this.#onMessage(agent.id, data));
    socket.on('close', () => {
      if (this.connections.get(agent.id) === socket) this.connections.delete(agent.id);
      this.#rejectAgentPending(agent.id, new Error('agent disconnected'));
    });
    socket.on('error', () => {});
    this.request(agent.id, 'snapshot', {}).catch(() => {});
  }

  isConnected(agentId) {
    return this.connections.has(agentId);
  }

  getSnapshot(agentId) {
    return this.snapshots.get(agentId) ?? null;
  }

  request(agentId, operation, payload, timeoutMs = this.requestTimeoutMs) {
    const socket = this.connections.get(agentId);
    if (!socket || socket.readyState !== 1) {
      const error = new Error('agent is offline');
      error.statusCode = 503;
      throw error;
    }
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        const error = new Error('agent request timed out');
        error.statusCode = 504;
        reject(error);
      }, timeoutMs);
      this.pending.set(requestId, { agentId, resolve, reject, timer });
      socket.send(JSON.stringify({ type: 'request', requestId, operation, payload }));
    });
  }

  #onMessage(agentId, data) {
    let message;
    try {
      message = JSON.parse(data.toString('utf8'));
    } catch {
      this.connections.get(agentId)?.close(4002, 'invalid JSON');
      return;
    }
    if (message.type === 'status' && Array.isArray(message.containers)) {
      this.snapshots.set(agentId, { containers: message.containers, receivedAt: new Date().toISOString() });
      return;
    }
    if (message.type !== 'response' || typeof message.requestId !== 'string') return;
    const pending = this.pending.get(message.requestId);
    if (!pending || pending.agentId !== agentId) return;
    clearTimeout(pending.timer);
    this.pending.delete(message.requestId);
    if (message.ok) pending.resolve(message.result);
    else {
      const error = new Error(message.error?.message || 'agent operation failed');
      error.code = message.error?.code;
      error.statusCode = message.error?.code === 'CONFLICT' ? 409 : 502;
      pending.reject(error);
    }
  }

  #rejectAgentPending(agentId, error) {
    for (const [requestId, pending] of this.pending) {
      if (pending.agentId !== agentId) continue;
      clearTimeout(pending.timer);
      this.pending.delete(requestId);
      pending.reject(error);
    }
  }
}
