# Agent in Docker

This guide runs the LabWarden agent as a container on a Docker host. Every 6 hours it lists the packages in the images of your running containers and sends the lists to the dashboard. Nothing is installed on the host itself.

The Docker agent scans **containers only**, not the host's own packages. To scan the host as well, use the [Linux agent](agent-linux.md) instead: it scans both. Use one or the other on a host, not both.

## What you need

- A Docker host with **Docker Compose v2**, on amd64 or arm64.
- Network access to the dashboard. Use its **`https://`** address: set up HTTPS first (see the [Compose guide](server-docker-compose.md), [Caddy](reverse-proxy-caddy.md) or [nginx](reverse-proxy-nginx.md)).
- An enrollment token from **Settings → Enrollment tokens**, with a short expiry and a host limit.

## How it reaches Docker safely

To see your containers, the agent needs to ask Docker. Access to the Docker socket (`/var/run/docker.sock`) is as good as root on the host, even when it is mounted read-only. So instead of giving the agent the socket, this setup puts a **socket proxy** in between:

```
labwarden-agent ──► docker-proxy (read-only: list containers and images) ──► /var/run/docker.sock
```

The proxy only answers requests to list and read containers and images. It refuses anything that would start, change or delete something. If the agent were ever compromised, it couldn't use Docker to take over the host.

## 1. Create a folder and a settings file

```bash
mkdir -p ~/labwarden-agent && cd ~/labwarden-agent
touch .env && chmod 600 .env
```

Put the token in `.env`, so it stays out of the Compose file:

```bash
LABWARDEN_TOKEN=<token>
```

## 2. Write `compose.yaml`

```yaml
services:
  # Read-only Docker API: the agent never holds the socket itself.
  docker-proxy:
    image: tecnativa/docker-socket-proxy:v0.5.0@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459
    restart: unless-stopped
    environment: { CONTAINERS: "1", IMAGES: "1", POST: "0" }
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    # No "ports:" here: only the agent, on this Compose network, can reach the proxy.

  labwarden-agent:
    # Release tag + multi-arch index digest. The Settings snippet always has
    # the one that matches your dashboard.
    image: ghcr.io/amanahlab/labwarden-agent:0.1.2@sha256:93dc485b0121503bef9608203b83686c36bc50ca486b0f5d899f99a9c594722b
    restart: unless-stopped
    depends_on: [docker-proxy]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    cap_add: [DAC_OVERRIDE]         # unpack container filesystems
    security_opt: [no-new-privileges:true]
    environment:
      LABWARDEN_URL: https://labwarden.example.lan
      LABWARDEN_TOKEN: ${LABWARDEN_TOKEN:-}
      LABWARDEN_HOST: docker-host-1    # name shown in the dashboard
      LABWARDEN_GROUP: homelab
      LABWARDEN_INTERVAL: "21600"      # seconds between scans
      LABWARDEN_DOCKER_URL: tcp://docker-proxy:2375
    volumes:
      - labwarden-agent-db:/var/lib/labwarden

volumes:
  labwarden-agent-db: {}
```

Set `LABWARDEN_URL` to your dashboard's address and `LABWARDEN_HOST` to the name you want in the dashboard. **Settings → Connect a host → Docker Compose** shows the same file with your address filled in.

## 3. Start it

```bash
docker compose up -d
docker compose logs -f labwarden-agent
```

The first scan starts right away. The log shows the agent enrolling, then each image it scans. The host appears under **Hosts** in the dashboard when the first scan is done.

## 4. Remove the token

After the first successful run, the agent keeps its own credential in the `labwarden-agent-db` volume and doesn't need the token any more. Delete the `LABWARDEN_TOKEN` line from `.env` and run `docker compose up -d`. Then revoke the token in Settings if you don't need it for other hosts.

Keep the volume: it holds the credential. If you delete it, click **Reset credential** on the host's page and start again with a fresh token.

## Options

| Option | Default | What it does |
|---|---|---|
| `LABWARDEN_HOST` | the container's ID | Name shown in the dashboard. Always set it. |
| `LABWARDEN_GROUP` | `default` | Group shown in the dashboard |
| `LABWARDEN_INTERVAL` | `21600` | Seconds between scans |
| `LABWARDEN_DOCKER_LABEL` | none | Only scan containers with this label, such as `labwarden.scan=true` |
| `LABWARDEN_CA_FILE` | none | CA certificate to trust for the dashboard (see below) |
| `TZ` | UTC | Time zone for the log |

To scan only some containers, set `LABWARDEN_DOCKER_LABEL: labwarden.scan=true` and add the label to those containers:

```yaml
    labels:
      labwarden.scan: "true"
```

### Dashboard with a self-signed or private certificate

Put the CA certificate next to `compose.yaml` as `ca.pem`, then add to the `labwarden-agent` service:

```yaml
    environment:
      LABWARDEN_CA_FILE: /etc/labwarden/ca.pem
    volumes:
      - ./ca.pem:/etc/labwarden/ca.pem:ro
```

## Updating

Set `image:` to the line from **Settings → Connect a host → Docker Compose** after you update the dashboard, then:

```bash
docker compose pull
docker compose up -d
```

## Without Compose

**Settings → Connect a host → Docker host** shows a one-line `docker run` command. It mounts the Docker socket read-only into the agent instead of using a proxy. That is simpler, but it gives the agent root-equivalent access to the host. Prefer the Compose setup above.

## Secure setup checklist

- **Use the socket proxy.** Never give the agent the Docker socket when you can avoid it, and never publish the proxy's port.
- **Use HTTPS** for `LABWARDEN_URL`. The agent doesn't follow redirects, so use the `https://` address directly.
- **Keep the token out of `compose.yaml`.** Put it in a `.env` readable only by you, and remove it after the first run.
- **Keep the hardening:** `read_only`, `cap_drop: [ALL]` with only `DAC_OVERRIDE` added back, and `no-new-privileges`.
- **Pin what you run.** Keep the socket proxy and the agent pinned by tag and digest, as in the file above. Never use `latest`.
- **One name per host.** Each host name can hold one credential. Don't run a Linux agent and a Docker agent under the same name.
- **Don't skip certificate checks.** Give the agent your CA with `LABWARDEN_CA_FILE` instead of falling back to http.
- **Act when a host is compromised or retired:** delete it in the dashboard or click **Reset credential**, and revoke the token that enrolled it.
