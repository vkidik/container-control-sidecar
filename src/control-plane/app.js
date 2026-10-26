import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createPublicKey, randomUUID } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { StateStore } from './state-store.js';
import { AuditLog } from './audit-log.js';
import { AgentAuthenticator } from './agent-auth.js';
import { AgentHub } from './agent-hub.js';
import { ConfirmationStore, SessionStore, isAllowedPeer } from './security.js';
import { readJson, routeMatch, sendJson, sendText } from './http.js';
import { WebAuthnService } from './webauthn-service.js';
import { assertAction, assertContainerName, assertIdentifier } from '../shared/validation.js';
import { canonicalContainers, sha256 } from '../shared/encoding.js';

const staticFiles = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
]);

function ensureAllowed(agent, container) {
  if (!agent || agent.revokedAt || !agent.allowedContainers.includes(container)) {
    const error = new Error('container is not allowed on this server');
    error.statusCode = 403;
    throw error;
  }
}

function publicAgent(agent, hub) {
  return {
    id: agent.id,
    displayName: agent.displayName,
    connected: hub.isConnected(agent.id),
    enrolledAt: agent.enrolledAt,
    revokedAt: agent.revokedAt,
    folderId: agent.folderId || null,
    allowedContainers: agent.allowedContainers,
    snapshot: hub.getSnapshot(agent.id),
  };
}

function publicApprovalRequest(request) {
  return {
    id: request.id,
    displayName: request.displayName,
    allowedContainers: request.allowedContainers,
    requestedAt: request.requestedAt,
    lastSeenAt: request.lastSeenAt,
    publicKeyFingerprint: sha256(request.publicKey).slice(0, 20),
  };
}

function agentEnrollment(request) {
  const encoded = String(request.headers['x-agent-enrollment'] || '');
  if (!encoded || encoded.length > 32 * 1024 || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error('invalid agent enrollment payload');
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new Error('invalid agent enrollment payload');
  }
  return {
    publicKey: String(payload.publicKey || ''),
    displayName: String(payload.displayName || ''),
    allowedContainers: Array.isArray(payload.allowedContainers) ? payload.allowedContainers : [],
    enrollmentToken: String(payload.enrollmentToken || ''),
  };
}

export async function createControlPlane(config) {
  const store = new StateStore(config.stateFile, { username: 'owner', displayName: 'Владелец' });
  await store.init();
  const audit = new AuditLog(config.auditFile);
  await audit.init();
  const sessions = new SessionStore({ idleMs: config.sessionIdleMs, absoluteMs: config.sessionAbsoluteMs });
  const confirmations = new ConfirmationStore(config.confirmationTtlMs);
  const hub = new AgentHub({ requestTimeoutMs: config.agentRequestTimeoutMs });
  const agentAuth = new AgentAuthenticator({ store });
  const webauthn = new WebAuthnService({ config, store, sessions, audit });
  const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024, perMessageDeflate: false });

  const handler = async (request, response, { agentOnly = false } = {}) => {
    const requestId = request.headers['x-request-id'] || randomUUID();
    response.setHeader('X-Request-Id', requestId);
    try {
      if (!isAllowedPeer(request.socket.remoteAddress, config.privateNetworkMode)) {
        return sendJson(response, 403, { error: 'request did not arrive through the configured private network boundary', requestId });
      }
      const url = new URL(request.url, config.origin);
      if (request.method === 'GET' && url.pathname === '/healthz') {
        return sendJson(response, 200, { ok: true });
      }
      if (agentOnly) return sendJson(response, 404, { error: 'agent gateway route not found', requestId });
      if (request.method === 'POST' && url.pathname === '/api/auth/register/options') {
        const body = await readJson(request);
        return sendJson(response, 200, await webauthn.registrationOptions(request, body));
      }
      if (request.method === 'POST' && url.pathname === '/api/auth/register/verify') {
        const body = await readJson(request);
        const result = await webauthn.verifyRegistration(request, body);
        return sendJson(response, 200, { ok: true, owner: result.owner, csrf: result.session.csrf }, { 'Set-Cookie': sessions.cookie(result.session) });
      }
      if (request.method === 'POST' && url.pathname === '/api/auth/login/options') {
        await readJson(request);
        return sendJson(response, 200, await webauthn.authenticationOptions());
      }
      if (request.method === 'POST' && url.pathname === '/api/auth/login/verify') {
        const result = await webauthn.verifyAuthentication(await readJson(request));
        return sendJson(response, 200, { ok: true, owner: result.owner, csrf: result.session.csrf }, { 'Set-Cookie': sessions.cookie(result.session) });
      }
      if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
        const session = sessions.require(request, { csrf: true });
        sessions.destroy(request);
        await audit.append({ actor: 'owner', event: 'session.destroyed', outcome: 'success', requestId, detail: { session: session.id.slice(0, 8) } });
        return sendJson(response, 200, { ok: true }, { 'Set-Cookie': sessions.clearCookie() });
      }
      if (request.method === 'GET' && url.pathname === '/api/auth/session') {
        const session = sessions.getFromRequest(request);
        if (!session) return sendJson(response, 401, { authenticated: false });
        return sendJson(response, 200, { authenticated: true, csrf: session.csrf, owner: await webauthn.publicOwner() });
      }
      if (request.method === 'GET' && staticFiles.has(url.pathname)) {
        const [file, contentType] = staticFiles.get(url.pathname);
        return sendText(response, 200, await readFile(path.join(config.publicDir, file), 'utf8'), contentType);
      }

      const session = sessions.require(request, { csrf: request.method !== 'GET' });
      if (request.method === 'GET' && url.pathname === '/api/servers') {
        const agents = (await store.listAgents()).map((agent) => publicAgent(agent, hub));
        return sendJson(response, 200, { servers: agents });
      }
      if (request.method === 'GET' && url.pathname === '/api/folders') {
        return sendJson(response, 200, { folders: await store.listFolders() });
      }
      if (request.method === 'POST' && url.pathname === '/api/folders') {
        const folder = await store.createFolder((await readJson(request)).name);
        await audit.append({ actor: 'owner', event: 'folder.created', target: folder.id, outcome: 'success', requestId, detail: { name: folder.name } });
        return sendJson(response, 201, { folder });
      }
      if (request.method === 'GET' && url.pathname === '/api/enrollment-requests') {
        const requests = (await store.listPendingAgents()).map(publicApprovalRequest);
        return sendJson(response, 200, { requests });
      }
      let match = routeMatch(url.pathname, '/api/folders/:folderId');
      if (request.method === 'PATCH' && match) {
        const folder = await store.renameFolder(match.folderId, (await readJson(request)).name);
        await audit.append({ actor: 'owner', event: 'folder.renamed', target: folder.id, outcome: 'success', requestId, detail: { name: folder.name } });
        return sendJson(response, 200, { folder });
      }
      if (request.method === 'DELETE' && match) {
        const result = await store.deleteFolder(match.folderId);
        await audit.append({ actor: 'owner', event: 'folder.deleted', target: result.folder.id, outcome: 'success', requestId, detail: { name: result.folder.name, movedAgents: result.movedAgents } });
        return sendJson(response, 200, { ok: true, movedAgents: result.movedAgents });
      }
      match = routeMatch(url.pathname, '/api/servers/:serverId/folder');
      if (request.method === 'PATCH' && match) {
        const body = await readJson(request);
        const folderId = body.folderId === null || body.folderId === '' ? null : String(body.folderId);
        const agent = await store.moveAgentToFolder(match.serverId, folderId);
        await audit.append({ actor: 'owner', event: 'agent.folder.changed', target: agent.id, outcome: 'success', requestId, detail: { folderId } });
        return sendJson(response, 200, { server: publicAgent(agent, hub) });
      }
      match = routeMatch(url.pathname, '/api/enrollment-requests/:serverId/approve');
      if (request.method === 'POST' && match) {
        const serverId = assertIdentifier(match.serverId, 'serverId');
        const agent = await store.approveAgentRequest(serverId);
        await audit.append({ actor: 'owner', event: 'agent.approval.granted', target: serverId, outcome: 'success', requestId, detail: { allowedContainers: agent.allowedContainers } });
        return sendJson(response, 200, { server: publicAgent(agent, hub) });
      }
      match = routeMatch(url.pathname, '/api/servers/:serverId/containers/:container/logs');
      if (request.method === 'GET' && match) {
        const serverId = assertIdentifier(match.serverId, 'serverId');
        const container = assertContainerName(match.container);
        const agent = await store.getAgent(serverId);
        ensureAllowed(agent, container);
        const tail = Math.max(1, Math.min(Number.parseInt(url.searchParams.get('tail') || '200', 10) || 200, 2000));
        const result = await hub.request(serverId, 'logs', { container, tail });
        await audit.append({ actor: 'owner', event: 'container.logs.read', target: `${serverId}/${container}`, outcome: 'success', requestId, detail: { tail } });
        return sendJson(response, 200, result);
      }
      if (request.method === 'POST' && url.pathname === '/api/actions/prepare') {
        const body = await readJson(request);
        const serverId = assertIdentifier(body.serverId, 'serverId');
        const container = assertContainerName(body.container);
        const action = assertAction(body.action);
        const agent = await store.getAgent(serverId);
        ensureAllowed(agent, container);
        if (!hub.isConnected(serverId)) {
          const error = new Error('agent is offline');
          error.statusCode = 503;
          throw error;
        }
        const prepared = confirmations.prepare(session.id, { serverId, container, action });
        await audit.append({ actor: 'owner', event: 'container.action.prepared', target: `${serverId}/${container}`, outcome: 'pending-confirmation', requestId, detail: { action, confirmationId: prepared.id } });
        return sendJson(response, 200, {
          confirmationId: prepared.id,
          expiresAt: new Date(prepared.expiresAt).toISOString(),
          summary: `${({ start: 'Запустить', stop: 'Остановить', restart: 'Перезапустить' })[action]} «${container}» на агенте «${agent.displayName}»`,
        });
      }
      if (request.method === 'POST' && url.pathname === '/api/actions/execute') {
        const body = await readJson(request);
        const confirmationId = String(body.confirmationId || '');
        const operation = confirmations.consume(confirmationId, session.id);
        const agent = await store.getAgent(operation.serverId);
        ensureAllowed(agent, operation.container);
        await audit.append({ actor: 'owner', event: 'container.action.dispatched', target: `${operation.serverId}/${operation.container}`, outcome: 'dispatched', requestId, detail: { action: operation.action, commandId: confirmationId } });
        try {
          const result = await hub.request(operation.serverId, 'command', { commandId: confirmationId, ...operation });
          await audit.append({ actor: 'owner', event: 'container.action.completed', target: `${operation.serverId}/${operation.container}`, outcome: result.outcome || 'success', requestId, detail: { action: operation.action, commandId: confirmationId } });
          return sendJson(response, 200, result);
        } catch (error) {
          await audit.append({ actor: 'owner', event: 'container.action.completed', target: `${operation.serverId}/${operation.container}`, outcome: 'error', requestId, detail: { action: operation.action, commandId: confirmationId, error: error.message } });
          throw error;
        }
      }
      if (request.method === 'GET' && url.pathname === '/api/audit') {
        const limit = Number.parseInt(url.searchParams.get('limit') || '100', 10);
        return sendJson(response, 200, { entries: await audit.recent(limit) });
      }
      return sendJson(response, 404, { error: 'not found', requestId });
    } catch (error) {
      const status = error.statusCode || (/invalid|required|must match|unknown/.test(error.message) ? 400 : 500);
      if (status >= 500) console.error(`[${requestId}]`, error);
      return sendJson(response, status, { error: error.message, requestId });
    }
  };

  const server = createServer((request, response) => handler(request, response));
  const agentServer = createServer((request, response) => handler(request, response, { agentOnly: true }));

  const processEnrollmentUpgrade = async (request, path) => {
    const requestId = request.headers['x-request-id'] || randomUUID();
    const serverId = assertIdentifier(request.headers['x-agent-id'], 'x-agent-id');
    const enrollment = agentEnrollment(request);
    const displayName = String(enrollment.displayName || serverId).trim().slice(0, 80) || serverId;
    const publicKey = enrollment.publicKey;
    const parsedKey = createPublicKey({ key: Buffer.from(publicKey, 'base64'), type: 'spki', format: 'der' });
    if (parsedKey.asymmetricKeyType !== 'ed25519') throw new Error('agent key must be Ed25519');
    const allowedContainers = canonicalContainers(enrollment.allowedContainers);
    if (allowedContainers.length === 0) throw new Error('agent allowlist must contain at least one container');
    const authenticatedId = agentAuth.authenticateApprovalRequest(request, path, {
      publicKey,
      displayName,
      allowedContainers,
    });
    if (authenticatedId !== serverId) throw new Error('agent id does not match signed request');

    if (enrollment.enrollmentToken) {
      const agent = await store.consumeEnrollment({
        token: enrollment.enrollmentToken,
        serverId,
        publicKey,
        allowedContainers,
      });
      await audit.append({ actor: `agent:${serverId}`, event: 'agent.enrolled', target: serverId, outcome: 'success', requestId });
      return { type: 'enrollment', status: 'approved', serverId: agent.id, allowedContainers: agent.allowedContainers };
    }

    if (!config.approvalEnrollmentEnabled) throw new Error('approval-based enrollment is disabled');
    const configuredAllowlist = config.approvalEnrollmentAllowedContainers || [];
    if (configuredAllowlist.length > 0 && allowedContainers.some((name) => !configuredAllowlist.includes(name))) {
      throw new Error('agent allowlist is not permitted for approval-based enrollment');
    }
    const result = await store.requestAgentApproval({ serverId, displayName, publicKey, allowedContainers });
    if (result.created) {
      await audit.append({ actor: `agent:${serverId}`, event: 'agent.approval.requested', target: serverId, outcome: 'pending', requestId, detail: { allowedContainers } });
    }
    if (result.status === 'approved') {
      return {
        type: 'enrollment',
        status: 'approved',
        serverId: result.agent.id,
        allowedContainers: result.agent.allowedContainers,
      };
    }
    return { type: 'enrollment', status: 'pending', serverId };
  };

  const handleUpgrade = async (request, socket, head) => {
    try {
      if (!isAllowedPeer(request.socket.remoteAddress, config.privateNetworkMode)) throw new Error('private network required');
      const url = new URL(request.url, config.origin);
      if (url.pathname === '/agent/connect') {
        const agent = await agentAuth.authenticate(request, url.pathname);
        return wss.handleUpgrade(request, socket, head, (websocket) => hub.register(agent, websocket));
      }
      if (url.pathname === '/agent/enroll') {
        const result = await processEnrollmentUpgrade(request, url.pathname);
        return wss.handleUpgrade(request, socket, head, (websocket) => {
          websocket.send(JSON.stringify(result), (error) => {
            if (error) return websocket.terminate();
            websocket.close(result.status === 'pending' ? 4003 : 1000, result.status);
          });
        });
      }
      throw new Error('unknown WebSocket endpoint');
    } catch {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
    }
  };
  server.on('upgrade', handleUpgrade);
  agentServer.on('upgrade', handleUpgrade);

  return { server, agentServer, store, audit, hub, sessions, confirmations };
}
