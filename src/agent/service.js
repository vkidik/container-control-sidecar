import { createPrivateKey, randomBytes, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import WebSocket from 'ws';
import { approvalRequestPayload, signaturePayload } from '../control-plane/agent-auth.js';
import { assertAction, assertContainerName } from '../shared/validation.js';
import { sameStringArray } from '../shared/encoding.js';
import { saveIdentity } from './identity.js';
import { agentWebSocketUrl } from './config.js';

async function tlsOptions(config) {
  return config.caFile ? { ca: await readFile(config.caFile) } : {};
}

async function postJson(url, body, options = {}) {
  const payload = Buffer.from(JSON.stringify(body));
  const transport = url.protocol === 'https:' ? https : http;
  const { headers: extraHeaders = {}, ...requestOptions } = options;
  return new Promise((resolve, reject) => {
    const request = transport.request(url, {
      method: 'POST',
      ...requestOptions,
      headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length, ...extraHeaders },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        let parsed = {};
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
        if (response.statusCode < 200 || response.statusCode >= 300) return reject(new Error(parsed.error || `HTTP ${response.statusCode}`));
        resolve(parsed);
      });
    });
    request.on('error', reject);
    request.end(payload);
  });
}

export class AgentService {
  constructor({ config, identity, docker, executor }) {
    this.config = config;
    this.identity = identity;
    this.docker = docker;
    this.executor = executor;
    this.socket = null;
    this.stopping = false;
  }

  async enrollIfNeeded() {
    if (this.identity.enrolled) return;
    if (!this.config.enrollmentToken) return this.#waitForApproval();
    const url = new URL('/api/agent/enroll', this.config.controlPlaneUrl);
    const result = await postJson(url, {
      serverId: this.config.serverId,
      publicKey: this.identity.publicKey,
      enrollmentToken: this.config.enrollmentToken,
      allowedContainers: this.config.allowedContainers,
    }, await tlsOptions(this.config));
    if (result.serverId !== this.config.serverId) throw new Error('control plane returned a different server id');
    if (!sameStringArray(result.allowedContainers, this.config.allowedContainers)) throw new Error('control plane returned a different allowlist');
    this.identity.enrolled = true;
    this.identity.enrolledAt = new Date().toISOString();
    await saveIdentity(this.config.identityFile, this.identity);
    console.log(`agent ${this.config.serverId} enrolled`);
  }

  async #waitForApproval() {
    const path = '/api/agent/approval-request';
    const url = new URL(path, this.config.controlPlaneUrl);
    let announced = false;
    let delay = 2000;
    while (!this.stopping && !this.identity.enrolled) {
      try {
        const timestamp = Date.now();
        const nonce = randomBytes(32).toString('base64url');
        const displayName = this.config.displayName || this.config.serverId;
        const signature = sign(
          null,
          Buffer.from(approvalRequestPayload({
            agentId: this.config.serverId,
            timestamp,
            nonce,
            path,
            publicKey: this.identity.publicKey,
            displayName,
            allowedContainers: this.config.allowedContainers,
          })),
          createPrivateKey(this.identity.privateKeyPem),
        ).toString('base64url');
        const result = await postJson(url, {
          serverId: this.config.serverId,
          displayName,
          publicKey: this.identity.publicKey,
          allowedContainers: this.config.allowedContainers,
        }, {
          ...(await tlsOptions(this.config)),
          headers: {
            'Content-Type': 'application/json',
            'X-Agent-Id': this.config.serverId,
            'X-Agent-Timestamp': String(timestamp),
            'X-Agent-Nonce': nonce,
            'X-Agent-Signature': signature,
          },
        });
        if (result.status === 'approved') {
          if (result.serverId !== this.config.serverId) throw new Error('control plane returned a different server id');
          if (!sameStringArray(result.allowedContainers, this.config.allowedContainers)) throw new Error('control plane returned a different allowlist');
          this.identity.enrolled = true;
          this.identity.enrolledAt = new Date().toISOString();
          await saveIdentity(this.config.identityFile, this.identity);
          console.log(`agent ${this.config.serverId} approved and enrolled`);
          return;
        }
        if (!announced) {
          console.log(`agent ${this.config.serverId} is waiting for owner approval`);
          announced = true;
        }
        delay = 5000;
      } catch (error) {
        console.error(`approval request failed: ${error.message}`);
        delay = Math.min(delay * 2, this.config.reconnectMaximumMs);
      }
      if (!this.stopping) await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  async start() {
    this.config.allowedContainers = await this.docker.composeProjectContainers(this.config.containerId);
    if (this.config.allowedContainers.length === 0) {
      throw new Error('the agent Docker Compose project has no application containers');
    }
    await this.enrollIfNeeded();
    if (this.stopping) return;
    let delay = 1000;
    while (!this.stopping) {
      try {
        await this.#connectOnce();
        delay = 1000;
      } catch (error) {
        if (!this.stopping) console.error(`connection failed: ${error.message}`);
      }
      if (!this.stopping) await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, this.config.reconnectMaximumMs);
    }
  }

  stop() {
    this.stopping = true;
    this.socket?.close(1000, 'shutdown');
  }

  async #connectOnce() {
    const path = '/agent/connect';
    const url = agentWebSocketUrl(this.config.controlPlaneUrl);
    const timestamp = Date.now();
    const nonce = randomBytes(32).toString('base64url');
    const signature = sign(null, Buffer.from(signaturePayload({ agentId: this.config.serverId, timestamp, nonce, path })), createPrivateKey(this.identity.privateKeyPem)).toString('base64url');
    const socket = new WebSocket(url, {
      headers: {
        'X-Agent-Id': this.config.serverId,
        'X-Agent-Timestamp': String(timestamp),
        'X-Agent-Nonce': nonce,
        'X-Agent-Signature': signature,
      },
      perMessageDeflate: false,
      maxPayload: 256 * 1024,
      ...(await tlsOptions(this.config)),
    });
    this.socket = socket;
    await new Promise((resolve, reject) => {
      socket.once('open', resolve);
      socket.once('error', reject);
    });
    console.log(`agent ${this.config.serverId} connected`);
    const statusTimer = setInterval(() => this.#sendStatus(socket).catch(() => {}), this.config.statusIntervalMs);
    await this.#sendStatus(socket);
    await new Promise((resolve) => {
      socket.on('message', (data) => this.#handleMessage(socket, data).catch((error) => console.error(`message error: ${error.message}`)));
      socket.once('close', resolve);
      socket.once('error', resolve);
    });
    clearInterval(statusTimer);
    this.socket = null;
  }

  async #handleMessage(socket, data) {
    let message;
    try { message = JSON.parse(data.toString('utf8')); } catch { return socket.close(4002, 'invalid JSON'); }
    if (message.type !== 'request' || typeof message.requestId !== 'string') return;
    try {
      let result;
      if (message.operation === 'snapshot') {
        result = { containers: await this.#snapshot() };
        socket.send(JSON.stringify({ type: 'status', containers: result.containers }));
      } else if (message.operation === 'logs') {
        const container = this.#allowed(message.payload?.container);
        const tail = Math.max(1, Math.min(Number(message.payload?.tail) || 200, 2000));
        result = { container, logs: await this.docker.logs(container, tail) };
      } else if (message.operation === 'command') {
        const container = this.#allowed(message.payload?.container);
        const action = assertAction(message.payload?.action);
        const commandId = String(message.payload?.commandId || '');
        if (!/^[A-Za-z0-9_-]{20,128}$/.test(commandId)) throw new Error('invalid commandId');
        result = await this.executor.run({ commandId, container, action });
        await this.#sendStatus(socket);
      } else {
        throw new Error('unsupported operation');
      }
      socket.send(JSON.stringify({ type: 'response', requestId: message.requestId, ok: true, result }));
    } catch (error) {
      socket.send(JSON.stringify({ type: 'response', requestId: message.requestId, ok: false, error: { code: error.code || 'AGENT_ERROR', message: error.message } }));
    }
  }

  #allowed(value) {
    const container = assertContainerName(value);
    if (!this.config.allowedContainers.includes(container)) {
      const error = new Error('container is not in the local allowlist');
      error.code = 'NOT_ALLOWED';
      throw error;
    }
    return container;
  }

  async #snapshot() {
    return Promise.all(this.config.allowedContainers.map(async (container) => {
      try { return await this.docker.inspect(container); }
      catch (error) { return { name: container, status: 'unavailable', running: false, error: error.message }; }
    }));
  }

  async #sendStatus(socket) {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'status', containers: await this.#snapshot() }));
  }
}
