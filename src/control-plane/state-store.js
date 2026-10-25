import { mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { canonicalContainers, constantEqual, sha256 } from '../shared/encoding.js';
import { assertIdentifier } from '../shared/validation.js';

function emptyState(owner) {
  return {
    version: 1,
    owner: { username: owner.username, displayName: owner.displayName, credentials: [] },
    bootstrapConsumed: false,
    enrollments: {},
    pendingAgents: {},
    agents: {},
    folders: {},
  };
}

function folderName(value) {
  const name = String(value || '').trim();
  if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) {
    const error = new Error('folder name must contain 1 to 80 printable characters');
    error.statusCode = 400;
    throw error;
  }
  return name;
}

function ensureFolders(state) {
  if (!state.folders) state.folders = {};
  return state.folders;
}

export class StateStore {
  #queue = Promise.resolve();

  constructor(file, owner) {
    this.file = file;
    this.owner = owner;
  }

  async init() {
    await mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    try {
      await readFile(this.file);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await this.#write(emptyState(this.owner));
    }
  }

  async read() {
    const parsed = JSON.parse(await readFile(this.file, 'utf8'));
    if (parsed.version !== 1) throw new Error(`unsupported state version: ${parsed.version}`);
    return parsed;
  }

  transaction(mutator) {
    const run = async () => {
      const release = await this.#acquireFileLock();
      try {
        const state = await this.read();
        const result = await mutator(state);
        await this.#write(state);
        return result;
      } finally {
        await release();
      }
    };
    const next = this.#queue.then(run, run);
    this.#queue = next.then(() => undefined, () => undefined);
    return next;
  }

  async #write(state) {
    const temporary = `${this.file}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, this.file);
    const handle = await open(this.file, 'r');
    await handle.sync();
    await handle.close();
  }

  async #acquireFileLock() {
    const lockFile = `${this.file}.lock`;
    const deadline = Date.now() + 5000;
    while (true) {
      try {
        const handle = await open(lockFile, 'wx', 0o600);
        await handle.writeFile(`${process.pid} ${Date.now()}\n`);
        await handle.close();
        return async () => { await unlink(lockFile).catch(() => {}); };
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        try {
          if (Date.now() - (await stat(lockFile)).mtimeMs > 30_000) {
            await unlink(lockFile);
            continue;
          }
        } catch (lockError) {
          if (lockError.code === 'ENOENT') continue;
          throw lockError;
        }
        if (Date.now() >= deadline) throw new Error('state store is locked by another process');
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
  }

  async getOwner() {
    return (await this.read()).owner;
  }

  async isBootstrapAllowed(token, expectedToken) {
    const state = await this.read();
    return state.owner.credentials.length === 0 && !state.bootstrapConsumed &&
      Boolean(expectedToken) && constantEqual(token, expectedToken);
  }

  async addCredential(credential, { consumeBootstrap = false } = {}) {
    return this.transaction((state) => {
      if (state.owner.credentials.some((item) => item.id === credential.id)) {
        throw new Error('credential already registered');
      }
      state.owner.credentials.push(credential);
      if (consumeBootstrap) state.bootstrapConsumed = true;
    });
  }

  async updateCredentialCounter(id, counter) {
    return this.transaction((state) => {
      const credential = state.owner.credentials.find((item) => item.id === id);
      if (!credential) throw new Error('credential not found');
      if (counter < credential.counter) throw new Error('credential counter moved backwards');
      credential.counter = counter;
      credential.lastUsedAt = new Date().toISOString();
    });
  }

  async issueEnrollment({ serverId, displayName, allowedContainers, ttlMs, now = Date.now() }) {
    assertIdentifier(serverId, 'server-id');
    const containers = canonicalContainers(allowedContainers);
    if (containers.length === 0) throw new Error('at least one allowed container is required');
    const token = `acp_enroll_${randomBytes(32).toString('base64url')}`;
    const enrollmentId = randomUUID();
    await this.transaction((state) => {
      if (state.agents[serverId] && !state.agents[serverId].revokedAt) {
        throw new Error(`active agent ${serverId} already exists; revoke it before replacement`);
      }
      state.enrollments[enrollmentId] = {
        id: enrollmentId,
        kind: 'single',
        serverId,
        displayName: displayName || serverId,
        allowedContainers: containers,
        tokenHash: sha256(token),
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + ttlMs).toISOString(),
        usedAt: null,
      };
    });
    return { token, enrollmentId, serverId, allowedContainers: containers, expiresAt: new Date(now + ttlMs).toISOString() };
  }

  async issueFleetEnrollment({ idPrefix = 'agent', displayNamePrefix = '', allowedContainers, ttlMs, maxUses, now = Date.now() }) {
    assertIdentifier(idPrefix, 'id-prefix');
    if (idPrefix.length > 43) throw new Error('id-prefix must be at most 43 characters');
    if (!Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > 1000) {
      throw new Error('max-uses must be an integer from 1 to 1000');
    }
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new Error('ttl must be positive');
    const containers = canonicalContainers(allowedContainers);
    if (containers.length === 0) throw new Error('at least one allowed container is required');
    const token = `acp_fleet_${randomBytes(32).toString('base64url')}`;
    const enrollmentId = randomUUID();
    const expiresAt = new Date(now + ttlMs).toISOString();
    await this.transaction((state) => {
      state.enrollments[enrollmentId] = {
        id: enrollmentId,
        kind: 'fleet',
        idPrefix,
        displayNamePrefix: String(displayNamePrefix || '').trim(),
        allowedContainers: containers,
        tokenHash: sha256(token),
        createdAt: new Date(now).toISOString(),
        expiresAt,
        maxUses,
        uses: [],
      };
    });
    return { token, enrollmentId, idPrefix, allowedContainers: containers, maxUses, expiresAt };
  }

  async consumeEnrollment({ token, serverId, publicKey, allowedContainers, now = Date.now() }) {
    return this.transaction((state) => {
      const enrollment = Object.values(state.enrollments).find((item) => constantEqual(item.tokenHash, sha256(token)));
      if (!enrollment) throw new Error('invalid enrollment token');
      const kind = enrollment.kind || 'single';
      if (kind === 'single' && enrollment.serverId !== serverId) throw new Error('invalid enrollment token');
      if (Date.parse(enrollment.expiresAt) < now) throw new Error('enrollment token expired');
      const requested = canonicalContainers(allowedContainers);
      if (JSON.stringify(requested) !== JSON.stringify(enrollment.allowedContainers)) {
        throw new Error('agent allowlist does not match enrollment allowlist');
      }
      const activeAgent = state.agents[serverId] && !state.agents[serverId].revokedAt
        ? state.agents[serverId]
        : null;
      const isSameAgent = activeAgent && activeAgent.publicKey === publicKey &&
        JSON.stringify(activeAgent.allowedContainers) === JSON.stringify(requested);
      if (kind === 'single' && enrollment.usedAt) {
        if (isSameAgent) return structuredClone(activeAgent);
        throw new Error('enrollment token already used');
      }
      if (kind === 'fleet') {
        if (!serverId.startsWith(`${enrollment.idPrefix}-`)) throw new Error('agent id does not match fleet enrollment prefix');
        if (!Array.isArray(enrollment.uses)) enrollment.uses = [];
        if (enrollment.uses.some((use) => use.serverId === serverId)) {
          if (isSameAgent) return structuredClone(activeAgent);
          throw new Error('fleet enrollment token already used by this agent id');
        }
        if (enrollment.uses.length >= enrollment.maxUses) throw new Error('fleet enrollment token exhausted');
      }
      if (activeAgent) {
        throw new Error(`active agent ${serverId} already exists`);
      }
      const usedAt = new Date(now).toISOString();
      if (kind === 'single') enrollment.usedAt = usedAt;
      else enrollment.uses.push({ serverId, usedAt });
      const displayName = kind === 'fleet' && enrollment.displayNamePrefix
        ? `${enrollment.displayNamePrefix} ${serverId.slice(enrollment.idPrefix.length + 1)}`
        : (enrollment.displayName || serverId);
      state.agents[serverId] = {
        id: serverId,
        displayName,
        publicKey,
        allowedContainers: enrollment.allowedContainers,
        enrolledAt: usedAt,
        revokedAt: null,
        folderId: null,
      };
      return structuredClone(state.agents[serverId]);
    });
  }

  async requestAgentApproval({ serverId, displayName, publicKey, allowedContainers, now = Date.now() }) {
    assertIdentifier(serverId, 'server-id');
    const containers = canonicalContainers(allowedContainers);
    if (containers.length === 0) throw new Error('at least one allowed container is required');
    const normalizedName = String(displayName || serverId).trim().slice(0, 80) || serverId;
    return this.transaction((state) => {
      if (!state.pendingAgents) state.pendingAgents = {};
      const activeAgent = state.agents[serverId] && !state.agents[serverId].revokedAt
        ? state.agents[serverId]
        : null;
      const sameAgent = activeAgent && activeAgent.publicKey === publicKey &&
        JSON.stringify(activeAgent.allowedContainers) === JSON.stringify(containers);
      if (sameAgent) return { status: 'approved', created: false, agent: structuredClone(activeAgent) };
      if (activeAgent) throw new Error(`active agent ${serverId} already exists`);

      const pending = state.pendingAgents[serverId];
      if (pending) {
        const sameRequest = pending.publicKey === publicKey &&
          JSON.stringify(pending.allowedContainers) === JSON.stringify(containers);
        if (!sameRequest) throw new Error(`agent approval request ${serverId} already exists with a different key or allowlist`);
        pending.lastSeenAt = new Date(now).toISOString();
        return { status: 'pending', created: false, request: structuredClone(pending) };
      }

      const requestedAt = new Date(now).toISOString();
      state.pendingAgents[serverId] = {
        id: serverId,
        displayName: normalizedName,
        publicKey,
        allowedContainers: containers,
        requestedAt,
        lastSeenAt: requestedAt,
      };
      return { status: 'pending', created: true, request: structuredClone(state.pendingAgents[serverId]) };
    });
  }

  async listPendingAgents() {
    const state = await this.read();
    return Object.values(state.pendingAgents || {});
  }

  async approveAgentRequest(serverId, now = Date.now()) {
    assertIdentifier(serverId, 'server-id');
    return this.transaction((state) => {
      if (!state.pendingAgents) state.pendingAgents = {};
      const pending = state.pendingAgents[serverId];
      if (!pending) throw new Error('pending agent request not found');
      if (state.agents[serverId] && !state.agents[serverId].revokedAt) {
        throw new Error(`active agent ${serverId} already exists`);
      }
      const enrolledAt = new Date(now).toISOString();
      state.agents[serverId] = {
        id: serverId,
        displayName: pending.displayName,
        publicKey: pending.publicKey,
        allowedContainers: pending.allowedContainers,
        enrolledAt,
        revokedAt: null,
        folderId: null,
      };
      delete state.pendingAgents[serverId];
      return structuredClone(state.agents[serverId]);
    });
  }

  async getAgent(serverId) {
    return (await this.read()).agents[serverId] ?? null;
  }

  async listAgents() {
    return Object.values((await this.read()).agents);
  }

  async listFolders() {
    const state = await this.read();
    return Object.values(state.folders || {}).sort((left, right) =>
      left.name.localeCompare(right.name, undefined, { sensitivity: 'base' }));
  }

  async createFolder(name, now = Date.now()) {
    const normalizedName = folderName(name);
    return this.transaction((state) => {
      const folders = ensureFolders(state);
      if (Object.values(folders).some((folder) => folder.name.localeCompare(normalizedName, undefined, { sensitivity: 'base' }) === 0)) {
        const error = new Error('folder with this name already exists');
        error.statusCode = 409;
        throw error;
      }
      const id = randomUUID();
      const timestamp = new Date(now).toISOString();
      folders[id] = { id, name: normalizedName, createdAt: timestamp, updatedAt: timestamp };
      return structuredClone(folders[id]);
    });
  }

  async renameFolder(folderId, name, now = Date.now()) {
    assertIdentifier(folderId, 'folderId');
    const normalizedName = folderName(name);
    return this.transaction((state) => {
      const folders = ensureFolders(state);
      const folder = folders[folderId];
      if (!folder) {
        const error = new Error('folder not found');
        error.statusCode = 404;
        throw error;
      }
      if (Object.values(folders).some((item) => item.id !== folderId && item.name.localeCompare(normalizedName, undefined, { sensitivity: 'base' }) === 0)) {
        const error = new Error('folder with this name already exists');
        error.statusCode = 409;
        throw error;
      }
      folder.name = normalizedName;
      folder.updatedAt = new Date(now).toISOString();
      return structuredClone(folder);
    });
  }

  async deleteFolder(folderId) {
    assertIdentifier(folderId, 'folderId');
    return this.transaction((state) => {
      const folders = ensureFolders(state);
      const folder = folders[folderId];
      if (!folder) {
        const error = new Error('folder not found');
        error.statusCode = 404;
        throw error;
      }
      let movedAgents = 0;
      for (const agent of Object.values(state.agents)) {
        if (agent.folderId === folderId) {
          agent.folderId = null;
          movedAgents += 1;
        }
      }
      delete folders[folderId];
      return { folder: structuredClone(folder), movedAgents };
    });
  }

  async moveAgentToFolder(serverId, folderId) {
    assertIdentifier(serverId, 'serverId');
    if (folderId !== null) assertIdentifier(folderId, 'folderId');
    return this.transaction((state) => {
      const agent = state.agents[serverId];
      if (!agent || agent.revokedAt) {
        const error = new Error('active agent not found');
        error.statusCode = 404;
        throw error;
      }
      if (folderId !== null && !ensureFolders(state)[folderId]) {
        const error = new Error('folder not found');
        error.statusCode = 404;
        throw error;
      }
      agent.folderId = folderId;
      return structuredClone(agent);
    });
  }

  async revokeAgent(serverId, now = Date.now()) {
    return this.transaction((state) => {
      const agent = state.agents[serverId];
      if (!agent || agent.revokedAt) throw new Error('active agent not found');
      agent.revokedAt = new Date(now).toISOString();
      return structuredClone(agent);
    });
  }
}
