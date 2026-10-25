import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DockerClient } from '../src/agent/docker-client.js';

function frame(text) {
  const body = Buffer.from(text);
  const header = Buffer.alloc(8);
  header[0] = 1;
  header.writeUInt32BE(body.length, 4);
  return Buffer.concat([header, body]);
}

test('Docker client uses only the local Unix socket for inspect, bounded logs, and action', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'acp-docker-'));
  const socketPath = path.join(directory, 'docker.sock');
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(`${request.method} ${request.url}`);
    if (request.url === '/containers/example-api/json') {
      response.setHeader('Content-Type', 'application/json');
      return response.end(JSON.stringify({ Name: '/example-api', Config: { Image: 'example:1' }, State: { Status: 'running', Running: true, Health: { Status: 'healthy' }, StartedAt: 'now' }, RestartCount: 2 }));
    }
    if (request.url.startsWith('/containers/example-api/logs?')) {
      response.setHeader('Content-Type', 'application/vnd.docker.raw-stream');
      return response.end(frame('hello\n'));
    }
    if (request.method === 'POST' && request.url === '/containers/example-api/restart?t=10') {
      response.writeHead(204);
      return response.end();
    }
    response.writeHead(404);
    response.end(JSON.stringify({ message: 'not found' }));
  });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const docker = new DockerClient(socketPath);
  assert.deepEqual(await docker.inspect('example-api'), {
    name: 'example-api', image: 'example:1', status: 'running', running: true,
    health: 'healthy', startedAt: 'now', restartCount: 2,
  });
  assert.equal(await docker.logs('example-api', 10), 'hello\n');
  assert.deepEqual(await docker.action('example-api', 'restart'), { outcome: 'success', statusCode: 204 });
  assert.equal(requests.some((value) => value.includes('tail=10')), true);
});

test('Docker client discovers only sibling services from the agent Compose project', async () => {
  const docker = new DockerClient('/unused');
  docker.request = async (_method, requestPath) => {
    if (requestPath === '/containers/self-agent/json') {
      return { body: Buffer.from(JSON.stringify({
        Id: 'self-id',
        Config: { Labels: { 'com.docker.compose.project': 'example', 'com.docker.compose.service': 'container-control-agent' } },
      })) };
    }
    assert.match(requestPath, /^\/containers\/json\?all=1&filters=/);
    return { body: Buffer.from(JSON.stringify([
      { Id: 'self-id', Names: ['/self-agent'], Labels: { 'com.docker.compose.service': 'container-control-agent' } },
      { Id: 'replica-id', Names: ['/agent-replica'], Labels: { 'com.docker.compose.service': 'container-control-agent' } },
      { Id: 'api-id', Names: ['/example-api'], Labels: { 'com.docker.compose.service': 'api' } },
    ])) };
  };
  assert.deepEqual(await docker.composeProjectContainers('self-agent'), ['example-api']);
});
