# Security architecture

This page explains how LabWarden protects your dashboard, your hosts and the data that moves between them. It is for people who run LabWarden, so it describes what each safeguard does for you and what you need to set up yourself, without going deep into the code.

For the short reference version, see the **Security model** section of the [README](../README.md#security-model). To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## The big picture

LabWarden has three parts, and each one is only trusted as far as it needs to be.

```
  Your browser ──── admin password ────►  Dashboard (server)  ◄──── host credential ──── Agent on each host
                     (session cookie)        • stores results                             • lists packages (Syft)
                                             • matches CVEs (Grype)                       • pushes them to the dashboard
```

- **The dashboard** is the only place that holds vulnerability data and the only place you sign in to.
- **Agents** run on your VMs and Docker hosts. They only *push* package lists to the dashboard. The dashboard never connects to an agent and never sends it commands, so even a compromised dashboard cannot run anything on your hosts.
- **You**, the admin, use a single password to reach the dashboard.

There are three kinds of secret, each with a narrow job:

| Secret | Who holds it | What it can do | What it cannot do |
|---|---|---|---|
| Admin password | You | Everything in the web UI | — |
| Enrollment token (`vxe_…`) | You, briefly, while installing an agent | Register a *new* host, within its expiry and use limit | Read anything, or report for any host |
| Host credential (`vxa_…`) | One agent, created at enrollment | Report SBOMs, events and run status for **its own host only** | Read the dashboard, or speak for any other host |

## Signing in to the dashboard

**A password is required.** The admin password must have at least 12 characters, and the placeholder `change-me` is rejected. If you don't set `LABWARDEN_ADMIN_PASSWORD`, the server generates a random one on first start. It stores it in the data volume as `admin-password`, readable only by the server (mode 0600), and never writes it to the log. Unlike a password in `.env`, it does not appear in `docker inspect`. Show it with `docker compose exec labwarden cat /data/admin-password`. If you set your own password, the server deletes the generated file. If you really want an open dashboard on a network you fully trust, you have to say so with `LABWARDEN_AUTH_DISABLED=true`, and the server repeats a warning about it every hour.

**Guessing is slowed down.** After 5 wrong passwords from one address, that address is locked out, and the lockout grows by 30 seconds with each further failure. The server also counts failures across *all* addresses. If more than 30 fail within 10 minutes, addresses that have already failed are paused, and the event appears under **Logs**. You can still sign in from an address that hasn't failed. This stops an attacker from spreading guesses over many addresses.

**Your real address is used, not one a client claims.** Requests can carry an `X-Forwarded-For` header that names an address, and anyone can forge it. LabWarden ignores it unless the request comes from a reverse proxy you listed in `LABWARDEN_TRUSTED_PROXIES`, so the lockout can't be dodged by inventing addresses.

**Sessions live on the server and can be ended.** Signing in creates a session that the server tracks. It ends:
- when you sign out
- after 24 hours without use, and after 7 days in any case
- for every session at once when you click **Settings → Sign out all sessions**, or change the admin password

**The session cookie is locked down.**
- Page scripts cannot read it.
- Your browser does not send it along with requests that start on other websites.
- Over HTTPS it is marked `Secure` and gets the `__Host-` name prefix, so it never travels over plain http and other sites on your domain cannot overwrite it.

**Other websites cannot act on your behalf.** If you are signed in and visit a malicious page, that page cannot make your browser change anything in LabWarden: requests that come from another site are refused.

**Little is shown before you sign in.** The health check (`/healthz`) only says whether the server is up, and the version number is only shown to signed-in users. That gives an outsider less to go on.

**The browser is told to be strict.** Every page is sent with headers that:
- only allow the dashboard's own scripts
- block embedding the dashboard in other sites
- turn off camera, microphone and location access
- keep API answers out of the browser cache
- over HTTPS, tell the browser to always use HTTPS for this dashboard from then on

## Connecting agents

### Enrollment: one token to join, one credential per host

1. In **Settings → Enrollment tokens** you create a token. It expires after 1 hour, 24 hours (the default), 7 days, or never, and can be limited to a number of hosts.
2. The installer gives the token to the agent, and the agent uses it once to *enroll*. The dashboard answers with a new **host credential** bound to that host's name.
3. From then on the agent uses only its credential. The token isn't needed any more, and revoking it doesn't affect hosts that already enrolled.

What this protects against:
- **One host cannot speak for another.** If a credential is used to report as a different host, the dashboard refuses (403) and records a warning. A stolen credential can only feed false data for its own host.
- **A host cannot be enrolled twice.** If someone tries to enroll a name that already has a credential, they get an error until you click **Reset agent credential** on that host's page.
- **Credentials are stored hashed.** The dashboard keeps only a hash of each token and credential, so a copy of its database does not hand out working secrets.
- **Revocation sticks.** A revoked enrollment token stays revoked after a restart, including the bootstrap token from `LABWARDEN_INGEST_TOKEN`. Deleting a host also revokes its credential.
- **Bad credentials are throttled.** An address that keeps presenting bad credentials is locked out for a while, and these failures are logged without filling the event log.

On the host, the agent keeps its credential in `/var/lib/labwarden/credential`, readable by root only. The credential is tied to the host name, so if you rename the machine, the agent enrolls again instead of reusing it.

### Agents can't change shared vulnerability data

Earlier versions had an endpoint that let an agent upload finished scan results. Those results could rewrite vulnerability details shared by every host. It has been removed. Agents now send only the list of packages (an SBOM), and the dashboard does all the vulnerability matching itself, with its own vulnerability database.

### Links are checked

Vulnerability data includes reference links. LabWarden keeps only `http` and `https` links, and the UI only turns those into clickable links, so a crafted entry can't slip a `javascript:` link into the dashboard.

## Installing agents safely

The installer runs as root, so it checks everything it downloads:

1. **Check the installer before running it.** The snippet in Settings downloads `install.sh` to a file, checks it against the SHA-256 shown on that page, and only then runs it. It replaces the old "pipe curl into sudo" pattern.
2. **Syft is verified.** The installer downloads the exact Syft release LabWarden is pinned to and checks it against SHA-256 checksums built into the installer, for both amd64 and arm64. It no longer runs a remote install script.
3. **The agent script is verified.** The dashboard writes the agent script's checksum into the installer it serves, and the installer refuses a download that doesn't match.
4. **Your settings are validated.** Before writing any configuration, the installer rejects odd values: a URL that isn't http(s), a token with unexpected characters, or a schedule containing extra lines. Values such as a group name with a quote in it are safely quoted.
5. **Unexpected answers stop the download.** If the dashboard answers with a redirect or an error, the installer stops with a clear message instead of saving whatever came back.

> **Note:** over plain http, the checksum in Settings comes from the same server as the installer. It catches a broken download, but not an attacker on your network who can change both. Use HTTPS (below) for that protection.

## What the agent does on your host

The agent runs as root (it has to read the whole filesystem and, optionally, Docker), so it is written defensively:

- **Secrets stay off the command line.** The token and credential are passed to `curl` through a private file, never as command arguments, so other users on the host can't see them in the process list.
- **It never evaluates host files.** The OS name is parsed from `/etc/os-release` as text instead of being run as shell code. The settings file `/etc/labwarden/agent.env` is only loaded if root owns it and nobody else can write to it.
- **Its lock is private.** The lock that stops two runs at once lives in `/var/lib/labwarden`, not in the shared `/tmp`.
- **What it prints is cleaned.** Control characters are stripped from what it sends and from what it logs, so a crafted package name or server reply can't mess with your terminal or logs.
- **Unpacked container images are kept harmless.** When it unpacks a container's filesystem to catalogue it, it doesn't keep the original owners or permissions, and clears any setuid or setgid bits.
- **It only talks http(s) and doesn't follow redirects** when it calls the dashboard.
- **The systemd service runs in a sandbox.** On systemd hosts the agent service:
  - cannot gain new privileges
  - sees most of the filesystem as read-only (only `/var/lib/labwarden` is writable)
  - gets a private `/tmp`
  - cannot change kernel settings or modules
  - can only use ordinary network and local sockets
  - runs with a reduced set of root capabilities

## Encrypting traffic (TLS)

Without TLS, the admin password, enrollment tokens, host credentials and package lists cross your network as plain text. LabWarden warns about this in three places: Settings shows a banner, and the installer and agent print a notice whenever the dashboard is plain http on another machine.

You have two options:

- **Let LabWarden serve HTTPS itself.** Set `LABWARDEN_TLS_CERT` and `LABWARDEN_TLS_KEY`. It uses TLS 1.2 or newer and picks up a renewed certificate within a minute (or at once on `SIGHUP`). If you use your own certificate authority, give agents and the installer its certificate with `LABWARDEN_CA_FILE`. The installer keeps a copy in `/etc/labwarden/ca.pem`.
- **Put it behind an HTTPS reverse proxy.** Set `LABWARDEN_TRUSTED_PROXIES` to the proxy's own address, so login throttling sees real client addresses. List only the proxy itself, not a whole Docker network. Also set `LABWARDEN_PUBLIC_URL` to the `https://` address.

## Docker access

Access to the Docker socket is effectively root on that host, even when it is mounted read-only. To limit this, a Docker agent can read Docker through a **socket proxy** instead of the socket itself. The Compose snippet in Settings sets this up with `tecnativa/docker-socket-proxy`, allowing only reading containers and images (`CONTAINERS=1 IMAGES=1 POST=0`). Point the agent at it with `LABWARDEN_DOCKER_URL`. The automated tests check that the agent works this way and that the proxy refuses anything that would change Docker.

## The containers themselves

The shipped `docker-compose.yml` runs the dashboard this way. The Docker agent runs the same way, both in the Compose snippet from Settings and as the testbed agent in `docker-compose.dev.yml`, which the automated tests check:
- with a **read-only root filesystem** (only the data volume and a small `/tmp` are writable)
- with **no Linux capabilities**. The agent keeps one, `DAC_OVERRIDE`, so it can unpack container filesystems.
- with **no-new-privileges**, so nothing inside can gain privileges

The dashboard runs as an unprivileged user (uid 10001).

## Keeping dependencies honest

- **Pinned images.** The dashboard image comes from GitHub's container registry (`ghcr.io/amanahlab/labwarden`), and `docker-compose.yml` pins it by tag *and* by digest. Every other image LabWarden ships or runs (the agent image, base and tool images, and the socket proxy) is pinned the same way, so a tag that is later changed upstream cannot sneak in different code.
- **Pinned tools.** Grype and Syft versions are pinned and updated together on purpose, along with Syft's checksums in the installer.
- **Automatic checks.** Every test run, including CI, checks the Go code with `govulncheck` and the web dependencies with `npm audit`.

## Your checklist

1. Use a strong admin password: keep the generated one, or set your own long random `LABWARDEN_ADMIN_PASSWORD`.
2. Serve the dashboard over HTTPS, either directly or through a reverse proxy with `LABWARDEN_TRUSTED_PROXIES` and `LABWARDEN_PUBLIC_URL` set.
3. Give enrollment tokens a short expiry and a host limit, and revoke them when you're done.
4. Install agents with the download, check, run snippet from Settings.
5. Use the socket proxy for Docker agents.
6. If a host is compromised or retired, delete it or click **Reset agent credential**, and revoke the token that enrolled it.
7. Look at **Logs** now and then for refused logins and rejected agent requests.

## Known limitations

LabWarden is built for a home lab or a small trusted network. These are known gaps that are tracked in the open:
- Hosts behind one NAT address share a lockout for bad credentials ([#8](https://github.com/amanahlab/Labwarden/issues/8)).
- A central scan can be given the name of an enrolled host ([#9](https://github.com/amanahlab/Labwarden/issues/9)).
- The container health check assumes the dashboard listens on all addresses ([#10](https://github.com/amanahlab/Labwarden/issues/10)).
- `LABWARDEN_COOKIE_SECURE=true` over plain http makes sign-in loop without an error ([#11](https://github.com/amanahlab/Labwarden/issues/11)).
- The systemd sandbox has not yet been checked on a real VM ([#14](https://github.com/amanahlab/Labwarden/issues/14)). The automated tests use cron.

## Upgrading from an earlier version

The hardened release deliberately breaks compatibility:
- Make sure the dashboard has an admin password of at least 12 characters. If you don't set one, the server now generates it on first start (see above).
- Re-run the installer on every VM and rebuild every Docker agent, so each one enrolls and gets its own credential. Your existing ingest tokens keep working as enrollment tokens.
- Pass `LABWARDEN_CA_FILE` and `LABWARDEN_DOCKER_URL` again if you use them, because the installer rewrites `agent.env` from the settings it is given.
