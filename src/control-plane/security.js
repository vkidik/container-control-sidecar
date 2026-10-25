import { randomBytes } from 'node:crypto';

function normalizeAddress(address = '') {
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

export function isLoopbackAddress(address) {
  const normalized = normalizeAddress(address);
  return normalized === '::1' || normalized.startsWith('127.');
}

export function isTailscaleAddress(address) {
  const normalized = normalizeAddress(address).toLowerCase();
  if (normalized.startsWith('fd7a:115c:a1e0:')) return true;
  const parts = normalized.split('.').map(Number);
  return parts.length === 4 && parts.every(Number.isInteger) &&
    parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127 &&
    parts.slice(2).every((value) => value >= 0 && value <= 255);
}

export function isPrivateAddress(address) {
  const normalized = normalizeAddress(address).toLowerCase();
  if (isLoopbackAddress(normalized)) return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  const parts = normalized.split('.').map(Number);
  if (parts.length !== 4 || !parts.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)) return false;
  return parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168);
}

export function isAllowedPeer(address, mode) {
  if (mode === 'loopback-proxy') return isLoopbackAddress(address);
  if (mode === 'docker-published') return isPrivateAddress(address);
  return isTailscaleAddress(address);
}

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map((part) => part.trim()).filter(Boolean).map((part) => {
    const index = part.indexOf('=');
    return index < 0 ? [part, ''] : [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
  }));
}

export class SessionStore {
  constructor({ idleMs, absoluteMs, now = () => Date.now() }) {
    this.idleMs = idleMs;
    this.absoluteMs = absoluteMs;
    this.now = now;
    this.sessions = new Map();
  }

  create() {
    const timestamp = this.now();
    const id = randomBytes(32).toString('base64url');
    const session = {
      id,
      csrf: randomBytes(24).toString('base64url'),
      createdAt: timestamp,
      lastSeenAt: timestamp,
      absoluteExpiresAt: timestamp + this.absoluteMs,
    };
    this.sessions.set(id, session);
    return session;
  }

  getFromRequest(request, { touch = true } = {}) {
    const id = parseCookies(request.headers.cookie).acp_session;
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session) return null;
    const timestamp = this.now();
    if (timestamp > session.absoluteExpiresAt || timestamp - session.lastSeenAt > this.idleMs) {
      this.sessions.delete(id);
      return null;
    }
    if (touch) session.lastSeenAt = timestamp;
    return session;
  }

  require(request, { csrf = false } = {}) {
    const session = this.getFromRequest(request);
    if (!session) {
      const error = new Error('authentication required');
      error.statusCode = 401;
      throw error;
    }
    if (csrf && request.headers['x-csrf-token'] !== session.csrf) {
      const error = new Error('invalid CSRF token');
      error.statusCode = 403;
      throw error;
    }
    return session;
  }

  destroy(request) {
    const id = parseCookies(request.headers.cookie).acp_session;
    if (id) this.sessions.delete(id);
  }

  cookie(session) {
    const maxAge = Math.floor(Math.min(this.idleMs, this.absoluteMs) / 1000);
    return `acp_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
  }

  clearCookie() {
    return 'acp_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
  }
}

export class ExpiringStore {
  constructor(ttlMs, now = () => Date.now()) {
    this.ttlMs = ttlMs;
    this.now = now;
    this.items = new Map();
  }

  create(value) {
    const id = randomBytes(24).toString('base64url');
    this.items.set(id, { value, expiresAt: this.now() + this.ttlMs });
    return { id, expiresAt: this.now() + this.ttlMs };
  }

  take(id) {
    const item = this.items.get(id);
    this.items.delete(id);
    if (!item || item.expiresAt < this.now()) return null;
    return item.value;
  }
}

export class ConfirmationStore extends ExpiringStore {
  prepare(sessionId, operation) {
    return this.create({ sessionId, operation });
  }

  consume(id, sessionId) {
    const value = this.take(id);
    if (!value || value.sessionId !== sessionId) {
      const error = new Error('confirmation is invalid, expired, or already used');
      error.statusCode = 409;
      throw error;
    }
    return value.operation;
  }
}

export const securityHeaders = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};
