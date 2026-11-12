// What a user copies to connect a host: shared by the Add host sheet and the
// reference on the Settings page.

// A release build embeds the agent image published with it (release.yml passes
// AGENT_IMAGE to the Dockerfile). Other builds use this pin of the latest
// release: tag + multi-arch index digest (docker buildx imagetools inspect).
export const agentImage = import.meta.env.VITE_AGENT_IMAGE || "ghcr.io/amanahlab/labwarden-agent:0.2.0@sha256:3cf85ba2ec4887d2bd162132f54e2b7d924fac776274c9e1276ba450a0e5bad9"

export const TTL_OPTIONS: [string, string][] = [
  ["1", "Expires in 1 hour"],
  ["24", "Expires in 24 hours"],
  ["168", "Expires in 7 days"],
  ["0", "Never expires"],
]

export type AgentKind = "vm" | "docker" | "compose"

// sha256 is of this dashboard's install.sh (GET /system); token is an
// enrollment token value. Both fall back to a placeholder the user replaces.
export function agentSnippets(opts: { sha256?: string; token?: string }): Record<AgentKind, string> {
  const url = window.location.origin
  const token = opts.token || "<token>"
  return {
    vm: `curl -fsSL -o lw-install.sh ${url}/install.sh
echo "${opts.sha256 || "<sha256>"}  lw-install.sh" | sha256sum -c
sudo LABWARDEN_URL=${url} LABWARDEN_TOKEN=${token} LABWARDEN_GROUP=homelab sh lw-install.sh`,
    docker: `docker run -d --name labwarden-agent --restart unless-stopped \\
  --read-only --tmpfs /tmp --cap-drop ALL --cap-add DAC_OVERRIDE \\
  --security-opt no-new-privileges:true \\
  -v /var/run/docker.sock:/var/run/docker.sock:ro \\
  -v labwarden-agent-db:/var/lib/labwarden \\
  -e LABWARDEN_URL=${url} -e LABWARDEN_TOKEN=${token} \\
  -e LABWARDEN_HOST=$(hostname) -e LABWARDEN_GROUP=homelab \\
  ${agentImage}`,
    compose: `services:
  # Read-only Docker API: the agent never holds the socket itself.
  docker-proxy:
    image: tecnativa/docker-socket-proxy:v0.5.0@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459
    restart: unless-stopped
    environment: { CONTAINERS: "1", IMAGES: "1", POST: "0" }
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
  labwarden-agent:
    image: ${agentImage}
    restart: unless-stopped
    depends_on: [docker-proxy]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    cap_add: [DAC_OVERRIDE]         # unpack container filesystems
    security_opt: [no-new-privileges:true]
    environment:
      LABWARDEN_URL: ${url}
      LABWARDEN_TOKEN: ${token}
      LABWARDEN_HOST: <host-name>      # name shown in the dashboard
      LABWARDEN_GROUP: homelab
      LABWARDEN_INTERVAL: "21600"    # seconds between scans
      LABWARDEN_DOCKER_URL: tcp://docker-proxy:2375
    volumes:
      - labwarden-agent-db:/var/lib/labwarden
volumes:
  labwarden-agent-db: {}`,
  }
}
