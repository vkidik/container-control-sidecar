import http from 'node:http';

export class DockerApiError extends Error {
  constructor(message, { statusCode = 0, indeterminate = false } = {}) {
    super(message);
    this.statusCode = statusCode;
    this.indeterminate = indeterminate;
  }
}

function decodeDockerStream(buffer) {
  const chunks = [];
  let offset = 0;
  while (offset + 8 <= buffer.length) {
    const streamType = buffer[offset];
    const length = buffer.readUInt32BE(offset + 4);
    if ((streamType !== 1 && streamType !== 2) || offset + 8 + length > buffer.length) {
      return buffer.toString('utf8');
    }
    chunks.push(buffer.subarray(offset + 8, offset + 8 + length));
    offset += 8 + length;
  }
  return Buffer.concat(chunks).toString('utf8');
}

export class DockerClient {
  constructor(socketPath = '/var/run/docker.sock') {
    this.socketPath = socketPath;
  }

  request(method, requestPath, { accepted = [200, 204], maximumBytes = 4 * 1024 * 1024 } = {}) {
    return new Promise((resolve, reject) => {
      const request = http.request({ socketPath: this.socketPath, path: requestPath, method }, (response) => {
        let size = 0;
        const chunks = [];
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > maximumBytes) {
            request.destroy(new DockerApiError('Docker response exceeded size limit', { statusCode: response.statusCode }));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          const body = Buffer.concat(chunks);
          if (!accepted.includes(response.statusCode)) {
            let detail = body.toString('utf8').slice(0, 1000);
            try { detail = JSON.parse(detail).message || detail; } catch {}
            reject(new DockerApiError(`Docker API ${response.statusCode}: ${detail}`, { statusCode: response.statusCode }));
            return;
          }
          resolve({ statusCode: response.statusCode, headers: response.headers, body });
        });
      });
      request.on('error', (error) => reject(error instanceof DockerApiError ? error : new DockerApiError(error.message, { indeterminate: true })));
      request.end();
    });
  }

  async inspect(container) {
    const response = await this.request('GET', `/containers/${encodeURIComponent(container)}/json`);
    const info = JSON.parse(response.body.toString('utf8'));
    return {
      name: String(info.Name || '').replace(/^\//, '') || container,
      image: info.Config?.Image || '',
      status: info.State?.Status || 'unknown',
      running: Boolean(info.State?.Running),
      health: info.State?.Health?.Status || null,
      startedAt: info.State?.StartedAt || null,
      restartCount: info.RestartCount || 0,
    };
  }

  async composeProjectContainers(selfContainer) {
    const selfResponse = await this.request('GET', `/containers/${encodeURIComponent(selfContainer)}/json`);
    const self = JSON.parse(selfResponse.body.toString('utf8'));
    const labels = self.Config?.Labels || {};
    const project = labels['com.docker.compose.project'];
    const agentService = labels['com.docker.compose.service'];
    if (!project || !agentService) throw new Error('agent must be started as a Docker Compose service');

    const filters = encodeURIComponent(JSON.stringify({ label: [`com.docker.compose.project=${project}`] }));
    const response = await this.request('GET', `/containers/json?all=1&filters=${filters}`);
    const containers = JSON.parse(response.body.toString('utf8'));
    return containers
      .filter((container) => container.Id !== self.Id)
      .filter((container) => container.Labels?.['com.docker.compose.service'] !== agentService)
      .map((container) => String(container.Names?.[0] || '').replace(/^\//, ''))
      .filter(Boolean)
      .sort();
  }

  async logs(container, tail) {
    const query = new URLSearchParams({ stdout: '1', stderr: '1', timestamps: '1', tail: String(tail) });
    const response = await this.request('GET', `/containers/${encodeURIComponent(container)}/logs?${query}`, { maximumBytes: 2 * 1024 * 1024 });
    const contentType = String(response.headers['content-type'] || '');
    return contentType.includes('application/vnd.docker.raw-stream') ? decodeDockerStream(response.body) : response.body.toString('utf8');
  }

  async action(container, action) {
    const query = action === 'start' ? '' : '?t=10';
    const response = await this.request('POST', `/containers/${encodeURIComponent(container)}/${action}${query}`, { accepted: [204, 304] });
    return { outcome: response.statusCode === 304 ? 'already-in-desired-state' : 'success', statusCode: response.statusCode };
  }
}
