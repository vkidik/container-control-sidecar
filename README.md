# Container Control Sidecar

Reusable Docker container control for projects deployed on unknown hosts. One
owner panel can receive outbound agents from many projects through one
permanent HTTPS/WebSocket tunnel.

All agent-to-panel traffic uses outbound WebSocket connections, including the
initial signed approval request, enrollment result, status snapshots, bounded
logs, and container commands. The public agent gateway does not expose REST
enrollment endpoints. The browser UI still talks to the local passkey-protected
panel backend so authorization and audit checks cannot be bypassed.

The repository publishes one image that contains both commands:

- `node src/control-plane/main.js` starts the passkey-protected panel;
- `node src/agent/main.js` starts the outbound agent, which automatically
  discovers only sibling services in its own Docker Compose project.

The panel supports project folders. Agents can be moved between folders and
still controlled individually. Deleting a folder moves its agents to
`Без папки`; it never deletes agents.

## Requirements

- Docker Engine or Docker Desktop;
- Docker Compose v2;
- a permanent HTTPS tunnel with WebSocket support, for example Tuna;
- for an agent host: access to `/var/run/docker.sock`.

No host networking is used. The same `docker-compose.yml` works on Linux servers,
macOS Docker Desktop and Windows Docker Desktop. The Docker socket sidecar is
intended for Linux containers.

## Configure your fork

Create a permanent tunnel to the agent gateway on local port `8788`. Do not
tunnel panel port `8787`.

In your GitHub fork open:

```text
Settings → Secrets and variables → Actions → Variables
```

Create this repository variable:

```text
Name:  CONTROL_PLANE_URL
Value: https://your-permanent-name.tuna.am
```

Use the origin only. Do not append an agent path, query parameters or
credentials. On every `main` push, `.github/workflows/publish-images.yml`
validates the variable and embeds it into the agent image as a Docker build
argument. Each fork therefore publishes an agent connected to that fork
owner's panel.

The published image name is:

```text
ghcr.io/<repository-owner>/container-control-sidecar:latest
```

After the first workflow run, make the GHCR package public if anonymous
servers should be able to pull it. A private package requires a read-only
GHCR token on every application server.

## Run with Docker Compose

Clone the repository, then:

```sh
cp .env.example .env
```

Edit `.env`. At minimum, replace:

```env
GHCR_REGISTRY=ghcr.io
GHCR_REPOSITORY=your-user/container-control-sidecar
IMAGE_TAG=latest
BOOTSTRAP_TOKEN=replace-with-a-long-random-one-time-token
```

Start the panel on a laptop or server:

```sh
docker compose up -d
```

Open `http://localhost:8787`, expand the initial setup section, enter the
bootstrap token and register a passkey. The bootstrap token is permanently
consumed after the first successful registration.

Start Tuna against the agent-only port:

```sh
tuna http 8788 --subdomain=your-permanent-name --https-redirect --rate-limit=10 --inspect=false
```

By default Compose publishes both ports only on `127.0.0.1`:

- `8787`: owner panel;
- `8788`: agent-only gateway for the tunnel.

The gateway returns `404` for panel and authentication routes. To operate the
panel on a remote server, keep it behind a private network or HTTPS reverse
proxy and set `WEBAUTHN_ORIGIN` to the exact URL opened in the browser. The
WebAuthn RP ID is derived automatically from that URL's hostname.

Panel data is stored in the `panel-data` Docker volume and survives updates.

The same `docker-compose.yml` also contains the agent. On the application host,
set:

```env
GHCR_REGISTRY=ghcr.io
GHCR_REPOSITORY=your-user/container-control-sidecar
IMAGE_TAG=latest
DOCKER_GID=999
```

On Linux, obtain `DOCKER_GID` with:

```sh
stat -c '%g' /var/run/docker.sock
```

Start only the agent with the same Compose project name as the application. For
example, if the application was started with project name `example`:

```sh
docker compose -p example --profile agent up -d agent
```

The project name is the security boundary: the agent automatically discovers
only containers with the same `com.docker.compose.project` label. The published
shared image already contains the `CONTROL_PLANE_URL` configured in GitHub
Actions, so application hosts do not configure the tunnel address.

On first start the agent:

1. creates a persistent random Ed25519 identity in its Docker volume;
2. sends a signed approval request through the shared tunnel;
3. appears in the owner panel as pending;
4. shows the Compose-project containers discovered by the agent for approval;
5. can then be placed into a project folder in the panel.

Recreating the application container does not change agent identity. Removing
the agent data volume creates a new identity that must be approved again.

## Updating

Pull repository changes and recreate the panel:

```sh
git pull
docker compose pull
docker compose up -d
```

Application servers can pull the published sidecar image directly or update it
with Watchtower. Changing `CONTROL_PLANE_URL` in GitHub requires rebuilding and
republishing the shared image; existing agents receive it after their image is
updated.

## Security boundary

- The public tunnel address is configuration, not a secret.
- The owner panel is protected by a passkey, CSRF checks and expiring sessions.
- New agents require explicit owner approval.
- Agent enrollment and WebSocket handshakes are signed with Ed25519 keys.
- The agent derives an exact container-name allowlist from Docker's
  `com.docker.compose.project` label, excludes its own service, and checks that
  list before every operation. Containers from other Compose projects are not
  exposed.
- Every mutation requires a short-lived confirmation and is appended to a
  hash-chained audit log.
- Mounting the Docker socket grants significant host control. The agent exposes
  only bounded operations, but a root administrator of the agent host can still
  inspect, replace or remove the sidecar.
