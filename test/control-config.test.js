import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/control-plane/config.js';

const base = {
  WEBAUTHN_ORIGIN: 'http://localhost:8787',
};

test('WebAuthn RP ID is derived from the configured origin', () => {
  const config = loadConfig(base);
  assert.equal(config.origin, 'http://localhost:8787');
  assert.equal(config.rpId, 'localhost');
});

test('Docker-published mode listens inside the container while Compose binds host loopback', () => {
  const config = loadConfig({
    ...base,
    PRIVATE_NETWORK_MODE: 'docker-published',
    LISTEN_HOST: '0.0.0.0',
    AGENT_LISTEN_HOST: '0.0.0.0',
  });
  assert.equal(config.listenHost, '0.0.0.0');
  assert.equal(config.agentListenHost, '0.0.0.0');
});

test('loopback-proxy mode still rejects a publicly bound listener', () => {
  assert.throws(() => loadConfig({ ...base, LISTEN_HOST: '0.0.0.0' }), /requires LISTEN_HOST to be loopback/);
});
