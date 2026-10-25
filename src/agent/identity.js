import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function loadOrCreateIdentity(file, serverId) {
  try {
    const identity = JSON.parse(await readFile(file, 'utf8'));
    if (serverId && identity.serverId !== serverId) throw new Error('stored identity belongs to a different AGENT_ID');
    return identity;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const identity = {
      version: 1,
      serverId: serverId || `agent-${randomBytes(10).toString('hex')}`,
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      enrolled: false,
      createdAt: new Date().toISOString(),
    };
    await saveIdentity(file, identity);
    return identity;
  }
}

export async function saveIdentity(file, identity) {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, file);
}
