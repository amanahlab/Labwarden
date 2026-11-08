# HTTPS with Caddy

This guide puts the LabWarden dashboard behind [Caddy](https://caddyserver.com), a web server that handles HTTPS certificates for you. Your browser and your agents talk HTTPS to Caddy, and Caddy passes the requests on to the dashboard.

It assumes you set up the dashboard with the [Docker Compose guide](server-docker-compose.md). Caddy runs as one more container in the same Compose project.

## How it fits together

```
browser, agents ──HTTPS──► caddy (172.30.0.10) ──HTTP, inside Docker──► labwarden:8080
```

- Caddy is the only thing your network can reach. The dashboard's own port is bound to the host's localhost, so the network can't bypass Caddy.
- Caddy gets a **fixed address** on the Compose network, and the dashboard is told to trust that one address. Only then does the dashboard believe Caddy when it says which client a request came from. It needs that to lock out password guessers by their real address.

## 1. Choose a name and a certificate

Pick the name you will use for the dashboard, such as `labwarden.example.lan`, and make it resolve to the Docker host, in your router's or Pi-hole's DNS, for example.

Then pick a certificate:

- **Caddy's own CA (`tls internal`)**: the easiest choice for a home lab. Caddy creates a private certificate authority and issues certificates from it. Browsers and agents need to be told to trust that CA once (step 5).
- **A certificate you already have**, from your own CA or from an ACME client. Put `fullchain.pem` and `privkey.pem` in a `certs` folder. Caddy reads the key as root inside the container, but without root's usual power to read other users' files, so make root its owner: `sudo chown root:root certs/privkey.pem && sudo chmod 600 certs/privkey.pem`.

> Caddy can also get free public certificates from Let's Encrypt automatically. That needs a real public domain, and either ports 80 and 443 open to the internet or a Caddy build with a DNS plugin. Opening the dashboard to the internet is not recommended, so this guide doesn't cover it.

## 2. Write the `Caddyfile`

Create `Caddyfile` next to `docker-compose.yml`:

```caddy
{
	# Caddy can't add its CA to the trust store from inside a container anyway.
	skip_install_trust
}

labwarden.example.lan {
	# Caddy's own CA. For your own certificate instead, use:
	#   tls /certs/fullchain.pem /certs/privkey.pem
	tls internal

	# Only answer clients from private networks (LAN, VPN, Docker).
	# 100.64.0.0/10 is Tailscale's range: remove it if you don't use Tailscale.
	@outside not remote_ip private_ranges 100.64.0.0/10
	abort @outside

	reverse_proxy labwarden:8080
}
```

You don't need to add any forwarding headers. Caddy sends the dashboard the original host name and the client's address, and it replaces any such headers a client tried to send.

You don't need to add security headers either. The dashboard sets its own, including HSTS once it is reached over HTTPS.

## 3. Add Caddy to the Compose project

Create `docker-compose.override.yml` next to `docker-compose.yml`. Compose merges it in automatically. If you already have one, add these parts to it.

```yaml
services:
  caddy:
    image: caddy:2.11.9-alpine@sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee
    restart: unless-stopped
    depends_on: [labwarden]
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"     # HTTP/3
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: [no-new-privileges:true]
    tmpfs: [/tmp]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      # - ./certs:/certs:ro     # only with your own certificate
      - caddy-data:/data        # certificates and Caddy's CA: keep this volume
      - caddy-config:/config
    networks:
      default:
        ipv4_address: 172.30.0.10

# A fixed subnet, so Caddy's address never changes.
networks:
  default:
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  caddy-data: {}
  caddy-config: {}
```

If `172.30.0.0/24` is already used on your network, pick another private subnet and change the Caddy address and `LABWARDEN_TRUSTED_PROXIES` to match.

## 4. Tell the dashboard about Caddy

Add or change these lines in `.env`:

```bash
# Only reachable from the host itself: everyone else goes through Caddy.
LABWARDEN_PORT=127.0.0.1:8080
# Caddy's fixed address. Trust nothing else.
LABWARDEN_TRUSTED_PROXIES=172.30.0.10
# The address you open in the browser.
LABWARDEN_PUBLIC_URL=https://labwarden.example.lan
```

Then apply everything. Because the network changes, take the project down first. Plain `down` keeps your data. **Don't add `-v`**, which would delete it.

```bash
docker compose down
docker compose up -d
docker compose logs caddy
```

## 5. Trust Caddy's CA (only with `tls internal`)

Copy the CA certificate out of the Caddy container:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./ca.pem
chmod 644 ca.pem    # a CA certificate is public; only its key is secret
```

- **Browsers:** import `ca.pem` into your computer's trust store, as "Caddy Local Authority". On Windows, double-click it and install it into *Trusted Root Certification Authorities*. On macOS, add it to the System keychain in Keychain Access and set it to *Always Trust*. Firefox has its own list under *Settings → Privacy & Security → Certificates*.
- **Agents:** give them the same file with `LABWARDEN_CA_FILE`. See the [Linux agent](agent-linux.md#dashboard-with-a-self-signed-or-private-certificate) and [Docker agent](agent-docker.md#dashboard-with-a-self-signed-or-private-certificate) guides.

The CA certificate is valid for 10 years. The certificates Caddy issues from it are short-lived and renewed automatically, so you don't need to do anything else. The CA's private key lives in the `caddy-data` volume: don't delete that volume, and don't share it.

## 6. Check it

1. Open `https://labwarden.example.lan` and sign in. The browser should show a valid certificate, without a warning.
2. Sign out, then sign in once with a **wrong** password on purpose.
3. Sign in properly and open **Logs**. You should see `failed admin login from <your computer's address>`.

   If it names a Docker address instead, such as `172.30.0.10` or `172.18.0.3`, the dashboard doesn't trust Caddy: check that `LABWARDEN_TRUSTED_PROXIES` matches the fixed address in the override file, and that `docker compose down` and `up -d` were run after adding it.

4. From another machine, `http://<docker-host>:8080` should no longer answer.

Then point your agents at `https://labwarden.example.lan`. Agents don't follow redirects, so always use the `https://` address with them, even though Caddy redirects http to https for browsers.

## Caddy installed on the host instead

If you already run Caddy as a system service on the Docker host, use the same site block, with `reverse_proxy 127.0.0.1:8080` and without the container parts.

The dashboard then sees Caddy's requests as coming from the Compose network's gateway. With the fixed subnet from step 3 (just the `networks:` part), that is `172.30.0.1`, so set `LABWARDEN_TRUSTED_PROXIES=172.30.0.1`.

Be aware of what that means: **every** program on the Docker host that connects to port 8080 appears to come from `172.30.0.1` too, so any of them could fake a client address. Only do this when you are the only one with a shell on that host. Otherwise, run Caddy in Compose as shown above.

## Secure setup checklist

- **Trust only Caddy's own address** in `LABWARDEN_TRUSTED_PROXIES`, never a whole subnet, and never the gateway unless Caddy runs on the host.
- **Bind the dashboard to localhost** (`LABWARDEN_PORT=127.0.0.1:8080`), so nobody can go around Caddy.
- **Set `LABWARDEN_PUBLIC_URL`** to the `https://` address.
- **Don't set `LABWARDEN_COOKIE_SECURE`.** The dashboard marks its cookie secure on its own when Caddy tells it the request came over HTTPS.
- **Keep the `private_ranges` rule**, so only your LAN and VPN can reach the dashboard, and don't forward ports 80 or 443 to it from your router.
- **Protect the `caddy-data` volume.** It holds Caddy's CA key. Anyone with it can issue certificates your devices trust.
- **Keep Caddy hardened and pinned:** read-only filesystem, only `NET_BIND_SERVICE`, `no-new-privileges`, image pinned by tag and digest. Update the pin on purpose.
- **Never tell agents to skip certificate checks.** Give them `ca.pem` instead.
