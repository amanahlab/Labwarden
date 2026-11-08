# Agent on a Linux host, without Docker

This guide installs the LabWarden agent directly on a Linux machine: a VM, a bare-metal server or a Raspberry Pi. The agent lists the packages on the machine with Syft every 6 hours and sends the list to the dashboard, which looks up the vulnerabilities.

If Docker is installed on the machine, the same agent also scans the images of its running containers. If you only want container scanning and would rather install nothing on the host, use the [Docker agent](agent-docker.md) instead. Use one or the other on a host, not both.

## What you need

- A Linux machine on **amd64 (x86_64) or arm64 (aarch64)**, with root access (`sudo`).
- `curl`, `gzip`, `tar` and `sha256sum`. Most distributions have them. On Alpine, run `apk add curl`.
- **systemd** or **cron**. The installer uses a systemd timer when it can, and cron otherwise.
- Network access to the dashboard. Use its **`https://`** address: set up HTTPS first (see the [Compose guide](server-docker-compose.md), [Caddy](reverse-proxy-caddy.md) or [nginx](reverse-proxy-nginx.md)).
- Internet access from the machine, once, to download Syft from GitHub.

## 1. Create an enrollment token

In the dashboard, open **Settings → Enrollment tokens** and create a token. Give it:

- a **short expiry**, such as 1 hour or 24 hours, and
- a **host limit** equal to the number of machines you are about to install.

The agent uses the token only once, to enroll. In return, the dashboard gives it a credential of its own, which it keeps on the machine. You can revoke the token as soon as your installs are done, and enrolled hosts keep working.

## 2. Download, check, run

Copy the commands from **Settings → Connect a host → Linux VM**. The page fills in your dashboard address and the installer's checksum. They look like this:

```bash
curl -fsSL -o lw-install.sh https://labwarden.example.lan/install.sh
echo "<sha256 from Settings>  lw-install.sh" | sha256sum -c
sudo LABWARDEN_URL=https://labwarden.example.lan LABWARDEN_TOKEN=<token> LABWARDEN_GROUP=homelab sh lw-install.sh
```

1. The first line downloads the installer to a file. It does not run it.
2. The second line checks the file against the checksum from Settings. If it prints anything other than `lw-install.sh: OK`, **stop**: the download is broken or was tampered with.
3. The third line runs the installer as root.

The installer then:

- downloads the pinned Syft release from GitHub and checks it against checksums built into the installer;
- downloads the agent script from your dashboard and checks it against the checksum the dashboard put in the installer;
- writes the settings, sets up the schedule and starts the first scan.

The host shows up in the dashboard a few minutes later, after its first scan.

> The token ends up in your shell history. That is one more reason to give it a short expiry: a stale copy is then worthless.

### Dashboard with a self-signed or private certificate

If your dashboard's certificate comes from your own CA, or from Caddy's `tls internal`, copy the CA certificate (`ca.pem`) to the machine first. Then let both steps trust it:

```bash
curl -fsSL --cacert ca.pem -o lw-install.sh https://labwarden.example.lan/install.sh
echo "<sha256 from Settings>  lw-install.sh" | sha256sum -c
sudo LABWARDEN_URL=https://labwarden.example.lan LABWARDEN_TOKEN=<token> \
  LABWARDEN_CA_FILE=./ca.pem sh lw-install.sh
```

The installer keeps a copy in `/etc/labwarden/ca.pem`, and the agent uses it from then on.

Don't work around certificate errors with `curl -k`. That turns off the very check that protects your token.

## What gets installed

| Path | What it is |
|---|---|
| `/usr/local/bin/labwarden-agent` | The agent script |
| `/usr/local/bin/syft` | Syft, the tool that lists packages |
| `/etc/labwarden/agent.env` | Settings, readable by root only. It still contains the enrollment token. |
| `/etc/labwarden/ca.pem` | Your CA certificate, if you gave one |
| `/var/lib/labwarden/` | The host's own credential and unsent results, readable by root only |
| `labwarden-agent.service` and `.timer` | The systemd schedule, every 6 hours plus a random delay of up to 15 minutes. Missed runs catch up after a reboot. |
| `/etc/cron.d/labwarden-agent` | The cron schedule on machines without systemd, logging to `/var/log/labwarden-agent.log` |

## Options

Pass these on the installer's command line, next to `LABWARDEN_URL` and `LABWARDEN_TOKEN`.

| Option | Default | What it does |
|---|---|---|
| `LABWARDEN_HOST` | the machine's host name | Name shown in the dashboard |
| `LABWARDEN_GROUP` | `default` | Group shown in the dashboard, such as `homelab` or `media` |
| `LABWARDEN_SCAN_PATHS` | `/` | Folders to scan, separated by spaces. Empty (`""`) turns off the filesystem scan. |
| `LABWARDEN_SCAN_DOCKER` | `auto` | `auto` scans containers when Docker is present. `true` or `false` forces it. |
| `LABWARDEN_DOCKER_URL` | none | A read-only Docker socket proxy to use instead of the Docker socket, such as `tcp://127.0.0.1:2375` |
| `LABWARDEN_SCHEDULE` | `*-*-* 00/6:00:00` | systemd schedule (an `OnCalendar` value) |
| `LABWARDEN_CRON` | every 6 hours at a random minute | cron schedule, used without systemd |
| `LABWARDEN_INTERVAL` | `21600` | Seconds between scans. If you change the schedule, change this to match, so the dashboard knows when a host has gone quiet. |
| `LABWARDEN_CA_FILE` | none | CA certificate to trust for the dashboard |
| `LABWARDEN_RUN_NOW` | `1` | Set to `0` to skip the first scan |

Example: scan only `/opt` and `/srv` once a day at 02:00, in the group `media`:

```bash
sudo LABWARDEN_URL=https://labwarden.example.lan LABWARDEN_TOKEN=<token> \
  LABWARDEN_GROUP=media LABWARDEN_SCAN_PATHS="/opt /srv" \
  LABWARDEN_SCHEDULE="*-*-* 02:00:00" LABWARDEN_INTERVAL=86400 sh lw-install.sh
```

## Checking that it works

- **In the dashboard:** the host appears under **Hosts**, and each run is listed under **Scans**. Errors and warnings from the agent appear under **Logs**.
- **On a systemd machine:**

  ```bash
  systemctl list-timers labwarden-agent.timer     # when the next scan runs
  journalctl -u labwarden-agent -f                # follow a scan
  sudo systemctl start labwarden-agent.service    # scan now
  ```

- **On a cron machine:** `tail -f /var/log/labwarden-agent.log`.

A scan of a whole machine usually takes one to a few minutes.

## Changing settings or updating

Run the download, check, run steps again with the new options. The installer rewrites `/etc/labwarden/agent.env` from the options you give it, so **pass every option again**, including `LABWARDEN_CA_FILE` and `LABWARDEN_DOCKER_URL` if you use them. A fresh token is fine: a host that already enrolled keeps its credential and doesn't use the token again.

## Renaming, moving or retiring a host

- **Renamed the machine?** The credential belongs to the old name, so the agent enrolls again under the new name. It needs a valid token in `agent.env`, so re-run the installer with a fresh token.
- **Re-installing the OS under the same name?** On the host's page in the dashboard, click **Reset credential**, then install the agent again. Without the reset, the dashboard refuses a second enrollment for a name that already has one.
- **Retiring the machine?** Uninstall the agent, then delete the host in the dashboard. Deleting the host also revokes its credential.

## Uninstalling

```bash
sudo sh lw-install.sh --uninstall
```

This removes the agent, its settings and its schedule. Syft and `/var/lib/labwarden` are left in place. Remove them yourself if you don't need them:

```bash
sudo rm -f /usr/local/bin/syft && sudo rm -rf /var/lib/labwarden
```

## Secure setup checklist

- **Use HTTPS.** Point `LABWARDEN_URL` at an `https://` address. Over plain http, the token, the host credential and the package lists cross the network in clear text, and the installer warns you about it. The agent and installer don't follow redirects, so use the `https://` address directly, not an http address that redirects.
- **Always download, check, then run.** Never pipe `curl` straight into `sudo sh`.
- **Use short-lived tokens with a host limit**, and revoke them in Settings once your installs are done.
- **Keep `/etc/labwarden` and `/var/lib/labwarden` root-only.** The installer sets this up. Don't loosen the permissions, and don't copy `agent.env` to other machines.
- **Don't skip certificate checks.** Give the agent your CA with `LABWARDEN_CA_FILE` instead of using `-k` or an http address.
- **Prefer systemd over cron.** On systemd the agent runs in a sandbox: most of the system is read-only to it, and it can't gain privileges or change kernel settings.
- **Leave the scan scope wide.** Scanning `/` finds the most. The agent already skips system folders such as `/proc`, `/sys` and `/tmp`, mounted drives under `/mnt` and `/media`, and Docker's own storage, so there is rarely a reason to narrow it.
- **Act when a machine is compromised or retired:** delete it in the dashboard or click **Reset credential**, and revoke the token that enrolled it.
