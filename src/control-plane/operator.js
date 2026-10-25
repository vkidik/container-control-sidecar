import path from 'node:path';
import { StateStore } from './state-store.js';
import { AuditLog } from './audit-log.js';

function argument(name, fallback = undefined) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

function usage() {
  console.error('Usage:\n  npm run operator -- enrollment --server-id ID --allow name1,name2 [--display-name NAME] [--ttl-minutes 10]\n  npm run operator -- fleet-enrollment --id-prefix PREFIX --allow name1,name2 --max-uses N [--display-name-prefix NAME] [--ttl-minutes 60]\n  npm run operator -- revoke --server-id ID');
  process.exit(2);
}

const command = process.argv[2];
if (!command) usage();
const dataDir = path.resolve(process.env.DATA_DIR || './data/control-plane');
const store = new StateStore(path.join(dataDir, 'state.json'), {
  username: 'owner',
  displayName: 'Владелец',
});
await store.init();
const audit = new AuditLog(path.join(dataDir, 'audit.jsonl'));
await audit.init();

try {
  if (command === 'enrollment') {
    const serverId = argument('server-id');
    const allowedContainers = String(argument('allow', '')).split(',');
    if (!serverId) usage();
    const ttlMinutes = Number.parseInt(argument('ttl-minutes', '10'), 10);
    const result = await store.issueEnrollment({
      serverId,
      displayName: argument('display-name', serverId),
      allowedContainers,
      ttlMs: ttlMinutes * 60_000,
    });
    await audit.append({ actor: 'local-operator', event: 'agent.enrollment.issued', target: serverId, outcome: 'success', detail: { allowedContainers: result.allowedContainers, expiresAt: result.expiresAt } });
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'fleet-enrollment') {
    const idPrefix = argument('id-prefix', 'agent');
    const allowedContainers = String(argument('allow', '')).split(',');
    const ttlMinutes = Number.parseInt(argument('ttl-minutes', '60'), 10);
    const maxUses = Number.parseInt(argument('max-uses', ''), 10);
    const result = await store.issueFleetEnrollment({
      idPrefix,
      displayNamePrefix: argument('display-name-prefix', ''),
      allowedContainers,
      ttlMs: ttlMinutes * 60_000,
      maxUses,
    });
    await audit.append({ actor: 'local-operator', event: 'agent.fleet-enrollment.issued', target: `fleet:${idPrefix}`, outcome: 'success', detail: { allowedContainers: result.allowedContainers, maxUses: result.maxUses, expiresAt: result.expiresAt } });
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'revoke') {
    const serverId = argument('server-id');
    if (!serverId) usage();
    const result = await store.revokeAgent(serverId);
    await audit.append({ actor: 'local-operator', event: 'agent.revoked', target: serverId, outcome: 'success' });
    console.log(JSON.stringify(result, null, 2));
  } else {
    usage();
  }
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
