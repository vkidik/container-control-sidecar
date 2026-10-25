import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const projectFile = (path) => new URL(`../${path}`, import.meta.url);

test('published agent gets its endpoint from the GitHub Actions variable', async () => {
  const [dockerfile, workflow] = await Promise.all([
    readFile(projectFile('Dockerfile'), 'utf8'),
    readFile(projectFile('.github/workflows/publish-images.yml'), 'utf8'),
  ]);
  assert.match(dockerfile, /ARG CONTROL_PLANE_URL/);
  assert.match(dockerfile, /ENV CONTROL_PLANE_URL=\$CONTROL_PLANE_URL/);
  assert.match(workflow, /CONTROL_PLANE_URL: \$\{\{ vars\.CONTROL_PLANE_URL \}\}/);
  assert.match(workflow, /build-args:[\s\S]*CONTROL_PLANE_URL=/);
  assert.match(workflow, /images: ghcr\.io\/\$\{\{ github\.repository_owner \}\}\/container-control-sidecar/);
  assert.match(workflow, /target: sidecar/);
  assert.doesNotMatch(workflow, /matrix\./);
});

test('panel compose publishes loopback ports without host networking', async () => {
  const compose = await readFile(projectFile('docker-compose.yml'), 'utf8');
  assert.match(compose, /127\.0\.0\.1/);
  assert.match(compose, /PRIVATE_NETWORK_MODE: docker-published/);
  assert.doesNotMatch(compose, /network_mode:\s*host/);
});

test('one Compose file contains both the panel and opt-in agent', async () => {
  const [compose, environment] = await Promise.all([
    readFile(projectFile('docker-compose.yml'), 'utf8'),
    readFile(projectFile('.env.example'), 'utf8'),
  ]);
  assert.match(compose, /services:[\s\S]*panel:/);
  assert.match(compose, /profiles: \[agent\]/);
  assert.match(compose, /\n  agent:/);
  const imageReferences = compose.match(/\$\{GHCR_REGISTRY:-ghcr\.io\}\/\$\{GHCR_REPOSITORY:\?GHCR_REPOSITORY is required\}:\$\{IMAGE_TAG:-latest\}/g) || [];
  assert.equal(imageReferences.length, 2);
  assert.doesNotMatch(compose, /:local/);
  assert.match(environment, /GHCR_REGISTRY=ghcr\.io/);
  assert.match(environment, /GHCR_REPOSITORY=your-github-user\/container-control-sidecar/);
  assert.match(environment, /IMAGE_TAG=latest/);
});

test('standalone deployment names are project-neutral', async () => {
  const files = await Promise.all([
    'package.json', 'README.md', 'docker-compose.yml',
    '.github/workflows/publish-images.yml',
  ].map(async (path) => readFile(projectFile(path), 'utf8')));
  assert.doesNotMatch(files.join('\n'), /atlanta/i);
});
