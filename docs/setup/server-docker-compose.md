# Dashboard with Docker Compose

This guide runs the LabWarden server, which holds the dashboard, the vulnerability database and all results, with Docker Compose on a Linux host.

## What you need

- A Linux host with **Docker Engine** and **Docker Compose v2.24 or newer** (`docker compose version`).
- At least **2 GB of RAM** and **10 GB of free disk**. The vulnerability database is several GB, and each matching worker uses about 115 MB.
- `git`, to fetch LabWarden. There are no prebuilt images yet: Compose builds the image on your host.
- Internet access from the host. The server downloads a fresh vulnerability database every night.

## 1. Get LabWarden

```bash
git clone https://github.com/amanahlab/Labwarden.git labwarden
cd labwarden
```

## 2. Create your settings file

```bash
scripts/dev-env.sh
```

This writes a `.env` file containing a random 24-character admin password and a bootstrap enrollment token. The file is readable only by you, and the script never prints the secrets. To see the password:

```bash
grep LABWARDEN_ADMIN_PASSWORD .env
```

Prefer to write it yourself? Copy `.env.example` to `.env`, run `chmod 600 .env`, and set `LABWARDEN_INGEST_TOKEN` to at least 16 characters: `docker-compose.yml` refuses to start without it. `LABWARDEN_ADMIN_PASSWORD` is optional. If you set it, use at least 12 characters. If you leave it out, the server generates one on first start and stores it in the data volume. To see it:

```bash
docker compose exec labwarden cat /data/admin-password
```

## 3. Start the dashboard

```bash
docker compose up -d --build
docker compose ps        # wait until the labwarden service shows "healthy"
```

Open `http://<host>:8080` and sign in with the password from `.env`, or the generated one. On first start the server downloads the vulnerability database, which takes a few minutes. **Settings → System** shows its progress.

> Only start the `labwarden` service. The `testbed` services in the same file are deliberately vulnerable test machines for development. Never start them with `--profile testbed` on a real setup.

## Settings you are most likely to change

All settings go in `.env`. Apply changes with `docker compose up -d`.

| Setting | What it does |
|---|---|
| `LABWARDEN_ADMIN_PASSWORD` | Admin password, at least 12 characters. If unset, the server generates one in `/data/admin-password`. Setting it deletes that file. Changing it signs out every session. |
| `LABWARDEN_PORT` | Where the dashboard is published on the host. `8080` listens on every interface. `127.0.0.1:8080` limits it to the host itself, which is what you want behind a reverse proxy. |
| `LABWARDEN_PUBLIC_URL` | The address you use to open the dashboard, such as `https://labwarden.example.lan`. Used for links in alerts and for the cross-site request check behind a proxy. |
| `LABWARDEN_TRUSTED_PROXIES` | The address of your reverse proxy, so login protection sees real client addresses. See the [Caddy](reverse-proxy-caddy.md) and [nginx](reverse-proxy-nginx.md) guides. |
| `LABWARDEN_TLS_CERT`, `LABWARDEN_TLS_KEY` | Let the dashboard serve HTTPS itself (see below). |
| `LABWARDEN_INGEST_TOKEN` | Bootstrap enrollment token that never expires. Optional: you can delete the line and create tokens in Settings instead. |
| `LABWARDEN_NOTIFY_URL` | Webhook for alerts about new critical or known-exploited findings (Slack, Discord, ntfy, …). Webhook URLs often contain a secret, so keep them only in `.env`. |
| `LABWARDEN_DB_UPDATE_AT`, `TZ` | When the nightly vulnerability database check runs (default `03:00` UTC). |
| `LABWARDEN_SCAN_WORKERS` | How many matching jobs run at once (default `2`). |

The full list is in the README under **Server configuration**.

## HTTPS without a reverse proxy

If you already have a certificate and key, for example from your own CA or from an ACME client, the dashboard can serve HTTPS directly.

1. Put `fullchain.pem` and `privkey.pem` in a `certs` folder next to `docker-compose.yml`. Keep nothing else there, such as a CA key. The dashboard runs as user 10001, so let it read the key:

   ```bash
   sudo chown 10001 certs/privkey.pem && sudo chmod 600 certs/privkey.pem
   ```

2. Create `docker-compose.override.yml` next to `docker-compose.yml`. Compose merges it in automatically:

   ```yaml
   services:
     labwarden:
       volumes:
         - ./certs/fullchain.pem:/certs/fullchain.pem:ro
         - ./certs/privkey.pem:/certs/privkey.pem:ro
   ```

3. Add to `.env`:

   ```bash
   LABWARDEN_TLS_CERT=/certs/fullchain.pem
   LABWARDEN_TLS_KEY=/certs/privkey.pem
   LABWARDEN_PORT=8443
   LABWARDEN_PUBLIC_URL=https://labwarden.example.lan:8443
   ```

4. Run `docker compose up -d`. The dashboard is now at `https://labwarden.example.lan:8443`. When you renew the certificate, replace the files: the server picks them up within a minute.

If the certificate comes from your own CA, agents need that CA's certificate. See `LABWARDEN_CA_FILE` in the agent guides.

## Updating

```bash
git pull
docker compose up -d --build
```

Read the release notes or the README's upgrade notes first. Some releases require agents to be re-installed.

## Backups

All state lives in one Docker volume, `labwarden_labwarden-data`: the database, the job queue, the stored package lists (SBOMs), the session key and a generated admin password. Stop the dashboard briefly so the database is consistent, then archive the volume. The vulnerability database and temporary files are skipped, because the server downloads them again. The generated admin password is skipped too, so the archive holds no plaintext password.

```bash
mkdir -p backups && chmod 700 backups
docker compose stop labwarden
docker run --rm -v labwarden_labwarden-data:/data:ro -v "$PWD/backups:/backup" \
  alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f \
  tar czf "/backup/labwarden-$(date +%F).tar.gz" -C /data --exclude ./grype-db --exclude ./tmp --exclude ./admin-password .
docker compose start labwarden
```

Treat backups as sensitive. They hold your inventory of hosts and vulnerabilities, and the key that protects admin sessions. Tokens and credentials inside are stored only as hashes.

After a restore without `LABWARDEN_ADMIN_PASSWORD` set, the server generates a new admin password. Read it again with `docker compose exec labwarden cat /data/admin-password`. The new password ends all sessions.

Never run `docker compose down -v`: the `-v` deletes the data volume.

## Secure setup checklist

- **Keep `.env` private.** It should be readable by you only (`chmod 600 .env`). Never commit it or paste it anywhere.
- **Use a long random admin password.** The server generates one if you don't set your own, and `scripts/dev-env.sh` makes one too. Don't use `LABWARDEN_AUTH_DISABLED=true` outside a throwaway lab.
- **Don't publish the dashboard to the whole network** unless clients need to reach it directly. Behind a reverse proxy, set `LABWARDEN_PORT=127.0.0.1:8080` so only the proxy can reach it.
- **Use HTTPS**: the dashboard's own TLS, [Caddy](reverse-proxy-caddy.md) or [nginx](reverse-proxy-nginx.md). Without it, passwords, tokens and credentials cross the network in clear text.
- **Don't expose LabWarden to the internet.** It is built for a home lab or small trusted network. For remote access, use a VPN such as WireGuard or Tailscale.
- **Keep the hardening in `docker-compose.yml`**: read-only root filesystem, no Linux capabilities, `no-new-privileges`. Don't remove it in an override file.
- **Remove the bootstrap token when you don't need it.** Revoke it in **Settings → Enrollment tokens** and delete `LABWARDEN_INGEST_TOKEN` from `.env`. Create short-lived tokens for each round of installs instead.
- **Watch Logs.** Failed logins and rejected agent requests show up there as warnings.
- **Back up regularly and keep backups private.**
- **Update regularly**, so you get security fixes and current scanners.
