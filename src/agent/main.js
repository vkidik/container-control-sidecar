import { loadAgentConfig } from './config.js';
import { loadOrCreateIdentity } from './identity.js';
import { DockerClient } from './docker-client.js';
import { OperationExecutor, OperationLedger } from './operation-ledger.js';
import { AgentService } from './service.js';

function argument(name, fallback = undefined) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

try {
  const config = loadAgentConfig();
  const ledger = new OperationLedger(config.ledgerFile);
  await ledger.init();
  if (process.argv[2] === 'reconcile') {
    const commandId = argument('command-id');
    const outcome = argument('outcome');
    if (!commandId || !outcome) throw new Error('reconcile requires --command-id and --outcome succeeded|failed');
    console.log(JSON.stringify(await ledger.reconcile(commandId, outcome, argument('note', '')), null, 2));
    process.exit(0);
  }
  const identity = await loadOrCreateIdentity(config.identityFile, config.serverId);
  config.serverId = identity.serverId;
  const docker = new DockerClient(config.dockerSocket);
  const executor = new OperationExecutor({ ledger, execute: ({ container, action }) => docker.action(container, action) });
  const service = new AgentService({ config, identity, docker, executor });
  process.on('SIGINT', () => service.stop());
  process.on('SIGTERM', () => service.stop());
  await service.start();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
