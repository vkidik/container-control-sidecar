import path from 'node:path';
function integer(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function boolean(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  if (String(value).toLowerCase() === 'true') return true;
  if (String(value).toLowerCase() === 'false') return false;
  throw new Error('boolean configuration values must be true or false');
}

export function loadConfig(env = process.env) {
  const dataDir = path.resolve(env.DATA_DIR || './data/control-plane');
  const configuredOrigin = String(env.WEBAUTHN_ORIGIN || '').trim();
  if (!configuredOrigin) throw new Error('WEBAUTHN_ORIGIN is required');
  let originUrl;
  try {
    originUrl = new URL(configuredOrigin);
  } catch {
    throw new Error('WEBAUTHN_ORIGIN must be an absolute URL');
  }
  if (originUrl.username || originUrl.password || originUrl.pathname !== '/' || originUrl.search || originUrl.hash) {
    throw new Error('WEBAUTHN_ORIGIN must contain only scheme, hostname and optional port');
  }
  const origin = originUrl.origin;
  const rpId = originUrl.hostname;
  const listenHost = env.LISTEN_HOST || '127.0.0.1';
  const privateNetworkMode = env.PRIVATE_NETWORK_MODE || 'loopback-proxy';
  if (!['loopback-proxy', 'docker-published', 'tailscale-source'].includes(privateNetworkMode)) {
    throw new Error('PRIVATE_NETWORK_MODE must be loopback-proxy, docker-published, or tailscale-source');
  }
  if (privateNetworkMode === 'loopback-proxy' && !['127.0.0.1', '::1', 'localhost'].includes(listenHost)) {
    throw new Error('loopback-proxy mode requires LISTEN_HOST to be loopback');
  }
  const agentGatewayEnabled = boolean(env.AGENT_GATEWAY_ENABLED, true);
  const agentListenHost = env.AGENT_LISTEN_HOST || '127.0.0.1';
  if (agentGatewayEnabled && privateNetworkMode !== 'docker-published' && !['127.0.0.1', '::1', 'localhost'].includes(agentListenHost)) {
    throw new Error('agent gateway must bind to loopback and be published through a tunnel or private proxy');
  }
  return {
    dataDir,
    stateFile: path.join(dataDir, 'state.json'),
    auditFile: path.join(dataDir, 'audit.jsonl'),
    publicDir: path.resolve(env.PUBLIC_DIR || './src/control-plane/public'),
    listenHost,
    listenPort: integer(env.LISTEN_PORT, 8080),
    agentGatewayEnabled,
    agentListenHost,
    agentListenPort: integer(env.AGENT_LISTEN_PORT, 8081),
    privateNetworkMode,
    rpName: 'Container Control',
    rpId,
    origin,
    bootstrapToken: env.BOOTSTRAP_TOKEN || '',
    sessionIdleMs: 600 * 1000,
    sessionAbsoluteMs: 1800 * 1000,
    ceremonyTtlMs: 120_000,
    confirmationTtlMs: 45_000,
    agentRequestTimeoutMs: integer(env.AGENT_REQUEST_TIMEOUT_SECONDS, 20) * 1000,
    approvalEnrollmentEnabled: boolean(env.APPROVAL_ENROLLMENT_ENABLED, false),
  };
}
