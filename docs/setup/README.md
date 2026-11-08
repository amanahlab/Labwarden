# Setting up LabWarden

These guides walk you through a complete LabWarden setup, from the dashboard to the agents on your hosts. Each one covers a single part and ends with the security practices that matter for it.

| Guide | Use it to |
|---|---|
| [Dashboard with Docker Compose](server-docker-compose.md) | Run the LabWarden server (dashboard) |
| [Agent on a Linux host, without Docker](agent-linux.md) | Scan a VM or bare-metal Linux machine, and optionally its containers |
| [Agent in Docker](agent-docker.md) | Scan the containers on a Docker host without installing anything on the host itself |
| [HTTPS with Caddy](reverse-proxy-caddy.md) | Put the dashboard behind Caddy, which can manage certificates for you |
| [HTTPS with nginx](reverse-proxy-nginx.md) | Put the dashboard behind nginx with your own certificates |

## Recommended order

1. **Start the dashboard** with [Docker Compose](server-docker-compose.md).
2. **Add HTTPS** before connecting any agents, either through [Caddy](reverse-proxy-caddy.md) or [nginx](reverse-proxy-nginx.md), or with the dashboard's own TLS (see the Compose guide). Agents send their credentials and package lists to the dashboard, so they should talk to it over HTTPS from the start.
3. **Connect your hosts.** On each host, pick one agent:
   - **Linux agent** if you can install software on the host. It scans the host's filesystem and, if Docker is present, its containers too.
   - **Docker agent** if you only want to scan containers, or prefer not to install anything on the host.

   Don't run both on the same host under the same name: each host name can hold only one agent credential.

## The secure setup at a glance

- A strong admin password, kept in a private `.env` file.
- HTTPS for both the browser and the agents.
- The dashboard's own port reachable only from the machine itself (or only from your proxy), not from the whole network.
- Short-lived enrollment tokens with a host limit.
- Agents installed with the download, check, run steps, and pointed at an `https://` address.
- A read-only Docker socket proxy wherever an agent needs to read Docker.
- Regular backups of the dashboard's data volume.

[Security architecture](../security-architecture.md) explains what each of these protects against.
