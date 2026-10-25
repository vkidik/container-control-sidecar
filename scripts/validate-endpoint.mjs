import { parseControlPlaneUrl } from '../src/agent/config.js';

const url = parseControlPlaneUrl(process.env.CONTROL_PLANE_URL);
console.log(`agent endpoint: ${url.origin}`);
