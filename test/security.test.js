import test from 'node:test';
import assert from 'node:assert/strict';
import { ConfirmationStore, SessionStore, isAllowedPeer, isPrivateAddress, isTailscaleAddress } from '../src/control-plane/security.js';

test('private network boundary accepts only the selected address class', () => {
  assert.equal(isTailscaleAddress('100.64.0.1'), true);
  assert.equal(isTailscaleAddress('100.127.255.255'), true);
  assert.equal(isTailscaleAddress('100.128.0.1'), false);
  assert.equal(isTailscaleAddress('fd7a:115c:a1e0::42'), true);
  assert.equal(isAllowedPeer('127.0.0.1', 'loopback-proxy'), true);
  assert.equal(isAllowedPeer('192.168.1.10', 'loopback-proxy'), false);
  assert.equal(isAllowedPeer('::ffff:100.100.1.2', 'tailscale-source'), true);
  assert.equal(isPrivateAddress('172.20.0.1'), true);
  assert.equal(isPrivateAddress('192.168.65.1'), true);
  assert.equal(isPrivateAddress('8.8.8.8'), false);
  assert.equal(isAllowedPeer('172.20.0.1', 'docker-published'), true);
  assert.equal(isAllowedPeer('8.8.8.8', 'docker-published'), false);
});

test('sessions are memory-only, expire on idle, and require CSRF for mutation', () => {
  let now = 1000;
  const sessions = new SessionStore({ idleMs: 100, absoluteMs: 500, now: () => now });
  const session = sessions.create();
  const request = { headers: { cookie: `acp_session=${session.id}`, 'x-csrf-token': session.csrf } };
  assert.equal(sessions.require(request, { csrf: true }).id, session.id);
  assert.throws(() => sessions.require({ headers: { cookie: request.headers.cookie } }, { csrf: true }), /CSRF/);
  now += 101;
  assert.equal(sessions.getFromRequest(request), null);
});

test('confirmation is bound to one session and consumed exactly once', () => {
  let now = 1000;
  const confirmations = new ConfirmationStore(100, () => now);
  const prepared = confirmations.prepare('session-a', { action: 'restart', container: 'api' });
  assert.throws(() => confirmations.consume(prepared.id, 'session-b'), /invalid/);
  const second = confirmations.prepare('session-a', { action: 'restart', container: 'api' });
  assert.deepEqual(confirmations.consume(second.id, 'session-a'), { action: 'restart', container: 'api' });
  assert.throws(() => confirmations.consume(second.id, 'session-a'), /already used/);
  const expired = confirmations.prepare('session-a', {});
  now += 101;
  assert.throws(() => confirmations.consume(expired.id, 'session-a'), /expired/);
});
