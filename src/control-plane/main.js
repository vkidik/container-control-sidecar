import { loadConfig } from './config.js';
import { createControlPlane } from './app.js';

try {
  const config = loadConfig();
  const { server, agentServer } = await createControlPlane(config);
  server.listen(config.listenPort, config.listenHost, () => {
    console.log(`control plane listening on ${config.listenHost}:${config.listenPort} (${config.privateNetworkMode})`);
  });
  if (config.agentGatewayEnabled) {
    agentServer.listen(config.agentListenPort, config.agentListenHost, () => {
      console.log(`agent-only gateway listening on ${config.agentListenHost}:${config.agentListenPort}`);
    });
  }
  const shutdown = (signal) => {
    console.log(`received ${signal}, shutting down`);
    let remaining = config.agentGatewayEnabled ? 2 : 1;
    const closed = () => {
      remaining -= 1;
      if (remaining === 0) process.exit(0);
    };
    server.close(closed);
    if (config.agentGatewayEnabled) agentServer.close(closed);
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
