import path from 'node:path';
import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { assertIdentifier } from '../shared/validation.js';

function envOrFile(env, name) {
  const direct = String(env[name] || '').trim();
  const file = String(env[`${name}_FILE`] || '').trim();
  if (direct && file) throw new Error(`${name} and ${name}_FILE are mutually exclusive`);
  if (!file) return direct;
  try {
    return readFileSync(path.resolve(file), 'utf8').trim();
  } catch (error) {
    throw new Error(`cannot read ${name}_FILE: ${error.message}`);
  }
}

function isLoopbackHostname(hostname) {
  const normalized = hostname.toLowerCase();
  if (normalized === 'localhost' || normalized === '[::1]') return true;
  const parts = normalized.split('.').map(Number);
  return parts.length === 4
    && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    && parts[0] === 127;
}

export function parseControlPlaneUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('CONTROL_PLANE_URL must be an absolute URL');
  }
  if (url.username || url.password) throw new Error('CONTROL_PLANE_URL must not contain credentials');
  if (url.search || url.hash) throw new Error('CONTROL_PLANE_URL must not contain a query or fragment');
  if (url.protocol === 'https:') return url;
  if (url.protocol === 'http:' && isLoopbackHostname(url.hostname)) return url;
  throw new Error('CONTROL_PLANE_URL must use https; http is allowed only for localhost or 127.0.0.0/8');
}

export function agentWebSocketUrl(controlPlaneUrl) {
  const url = new URL('/agent/connect', controlPlaneUrl);
  url.protocol = controlPlaneUrl.protocol === 'http:' ? 'ws:' : 'wss:';
  return url;
}

export function loadAgentConfig(env = process.env, getHostname = hostname) {
  const configuredServerId = envOrFile(env, 'AGENT_ID');
  const serverId = configuredServerId ? assertIdentifier(configuredServerId, 'AGENT_ID') : null;
  const controlPlaneUrl = parseControlPlaneUrl(envOrFile(env, 'CONTROL_PLANE_URL'));
  const containerId = String(getHostname() || '').trim();
  if (!containerId) throw new Error('agent must run inside a Docker container');
  const dataDir = path.resolve(env.AGENT_DATA_DIR || './data/agent');
  return {
    serverId,
    controlPlaneUrl,
    containerId,
    allowedContainers: [],
    enrollmentToken: envOrFile(env, 'ENROLLMENT_TOKEN'),
    displayName: envOrFile(env, 'AGENT_DISPLAY_NAME'),
    dataDir,
    identityFile: path.join(dataDir, 'identity.json'),
    ledgerFile: path.join(dataDir, 'operations.json'),
    dockerSocket: env.DOCKER_SOCKET || '/var/run/docker.sock',
    caFile: env.CONTROL_PLANE_CA_FILE ? path.resolve(env.CONTROL_PLANE_CA_FILE) : null,
    statusIntervalMs: 15_000,
    reconnectMaximumMs: 30_000,
  };
}
