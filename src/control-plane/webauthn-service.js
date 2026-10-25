import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { ExpiringStore } from './security.js';

export class WebAuthnService {
  constructor({ config, store, sessions, audit }) {
    this.config = config;
    this.store = store;
    this.sessions = sessions;
    this.audit = audit;
    this.ceremonies = new ExpiringStore(config.ceremonyTtlMs);
  }

  async registrationOptions(request, { bootstrapToken, label }) {
    const existingSession = this.sessions.getFromRequest(request);
    const bootstrap = existingSession ? false : await this.store.isBootstrapAllowed(bootstrapToken, this.config.bootstrapToken);
    if (!existingSession && !bootstrap) {
      const error = new Error('active session or valid bootstrap token required');
      error.statusCode = 403;
      throw error;
    }
    const owner = await this.store.getOwner();
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: owner.username,
      userDisplayName: owner.displayName,
      userID: Buffer.from(`owner:${owner.username}`),
      attestationType: 'none',
      excludeCredentials: owner.credentials.map((credential) => ({ id: credential.id, transports: credential.transports })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      timeout: this.config.ceremonyTtlMs,
    });
    const ceremony = this.ceremonies.create({
      kind: 'registration',
      challenge: options.challenge,
      bootstrap,
      sessionId: existingSession?.id ?? null,
      label: String(label || 'Passkey').slice(0, 80),
    });
    return { ceremonyId: ceremony.id, options };
  }

  async verifyRegistration(request, { ceremonyId, response, bootstrapToken }) {
    const ceremony = this.ceremonies.take(ceremonyId);
    if (!ceremony || ceremony.kind !== 'registration') {
      const error = new Error('registration ceremony expired or already used');
      error.statusCode = 409;
      throw error;
    }
    if (ceremony.bootstrap) {
      if (!await this.store.isBootstrapAllowed(bootstrapToken, this.config.bootstrapToken)) {
        const error = new Error('bootstrap authorization is no longer valid');
        error.statusCode = 403;
        throw error;
      }
    } else {
      const session = this.sessions.require(request, { csrf: true });
      if (session.id !== ceremony.sessionId) throw new Error('registration session mismatch');
    }
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: this.config.origin,
      expectedRPID: this.config.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo) throw new Error('passkey registration could not be verified');
    const info = verification.registrationInfo;
    await this.store.addCredential({
      id: info.credential.id,
      publicKey: Buffer.from(info.credential.publicKey).toString('base64'),
      counter: info.credential.counter,
      transports: response.response?.transports || info.credential.transports || [],
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      label: ceremony.label,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
    }, { consumeBootstrap: ceremony.bootstrap });
    const session = this.sessions.create();
    await this.audit.append({ actor: 'owner', event: 'passkey.registered', outcome: 'success', detail: { label: ceremony.label } });
    return { session, owner: await this.publicOwner() };
  }

  async authenticationOptions() {
    const owner = await this.store.getOwner();
    if (owner.credentials.length === 0) {
      const error = new Error('no passkey is registered; complete bootstrap registration');
      error.statusCode = 409;
      throw error;
    }
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpId,
      allowCredentials: owner.credentials.map((credential) => ({ id: credential.id, transports: credential.transports })),
      userVerification: 'required',
      timeout: this.config.ceremonyTtlMs,
    });
    const ceremony = this.ceremonies.create({ kind: 'authentication', challenge: options.challenge });
    return { ceremonyId: ceremony.id, options };
  }

  async verifyAuthentication({ ceremonyId, response }) {
    const ceremony = this.ceremonies.take(ceremonyId);
    if (!ceremony || ceremony.kind !== 'authentication') {
      const error = new Error('authentication ceremony expired or already used');
      error.statusCode = 409;
      throw error;
    }
    const owner = await this.store.getOwner();
    const stored = owner.credentials.find((credential) => credential.id === response.id);
    if (!stored) {
      const error = new Error('unknown passkey');
      error.statusCode = 403;
      throw error;
    }
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: this.config.origin,
      expectedRPID: this.config.rpId,
      credential: {
        id: stored.id,
        publicKey: Buffer.from(stored.publicKey, 'base64'),
        counter: stored.counter,
        transports: stored.transports,
      },
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.authenticationInfo.userVerified) throw new Error('passkey authentication failed');
    await this.store.updateCredentialCounter(stored.id, verification.authenticationInfo.newCounter);
    const session = this.sessions.create();
    await this.audit.append({ actor: 'owner', event: 'session.created', outcome: 'success', detail: { credential: stored.label } });
    return { session, owner: await this.publicOwner() };
  }

  async publicOwner() {
    const owner = await this.store.getOwner();
    return { username: owner.username, displayName: owner.displayName, passkeyCount: owner.credentials.length };
  }
}
