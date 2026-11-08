# HTTPS with nginx

This guide puts the LabWarden dashboard behind [nginx](https://nginx.org). Your browser and your agents talk HTTPS to nginx, and nginx passes the requests on to the dashboard.

Unlike Caddy, nginx doesn't get certificates by itself: you bring your own. If you don't have a certificate and don't want to manage one, the [Caddy guide](reverse-proxy-caddy.md) is easier.

It assumes you set up the dashboard with the [Docker Compose guide](server-docker-compose.md). nginx runs as one more container in the same Compose project.

## How it fits together

```
browser, agents ──HTTPS──► nginx (172.30.0.10) ──HTTP, inside Docker──► labwarden:8080
```

- nginx is the only thing your network can reach. The dashboard's own port is bound to the host's localhost, so the network can't bypass nginx.
- nginx gets a **fixed address** on the Compose network, and the dashboard is told to trust that one address. Only then does the dashboard believe nginx when it says which client a request came from. It needs that to lock out password guessers by their real address.

## 1. Get a certificate

Pick the name you will use for the dashboard, such as `labwarden.example.lan`, and make it resolve to the Docker host, in your router's or Pi-hole's DNS, for example.

Put the certificate in a `certs` folder next to `docker-compose.yml`:

- `certs/fullchain.pem`: the certificate, followed by any intermediate certificates
- `certs/privkey.pem`: its private key

It can come from your own CA, or from an ACME client such as certbot or acme.sh using a DNS challenge.

nginx reads the key as root inside the container, but without root's usual power to read other users' files. So make root the key's owner, and nobody else able to read it:

```bash
sudo chown root:root certs/privkey.pem && sudo chmod 600 certs/privkey.pem
```

<details>
<summary>No certificate yet? Make a small private CA with openssl.</summary>

```bash
mkdir -p certs && cd certs
# 1. Your own CA, valid for 10 years. Keep ca.key private, ideally offline.
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=Homelab CA" \
  -keyout ca.key -out ca.pem
# 2. A certificate for the dashboard, valid for 1 year.
printf 'subjectAltName=DNS:labwarden.example.lan\nextendedKeyUsage=serverAuth\n' > san.ext
openssl req -newkey rsa:2048 -nodes -subj "/CN=labwarden.example.lan" \
  -keyout privkey.pem -out labwarden.csr
openssl x509 -req -in labwarden.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -extfile san.ext -out fullchain.pem
chmod 600 ca.key
sudo chown root:root privkey.pem && sudo chmod 600 privkey.pem
cd ..
```

Then trust `ca.pem` in your browsers and give it to your agents (step 5). Move `ca.key` somewhere safe: anyone who has it can make certificates your devices trust. Repeat step 2 before the year is up.

</details>

## 2. Write the nginx configuration

Create `nginx/labwarden.conf` next to `docker-compose.yml`:

```nginx
# Don't announce the nginx version.
server_tokens off;

# Plain http: send browsers to https. (Agents don't follow redirects:
# always give them the https address.)
server {
    listen 80;
    server_name labwarden.example.lan;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name labwarden.example.lan;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;

    # Only answer clients from private networks (LAN, VPN, Docker).
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    allow 100.64.0.0/10;    # Tailscale
    deny  all;

    # Agents upload package lists of up to 256 MB, and matching a big one
    # can take a few minutes. nginx defaults to 1 MB and 60 seconds.
    client_max_body_size 256m;
    proxy_read_timeout   300s;
    proxy_send_timeout   300s;

    # Docker's own DNS, so nginx finds the dashboard again after it is recreated.
    resolver 127.0.0.11 valid=30s;
    set $labwarden http://labwarden:8080;

    location / {
        proxy_pass $labwarden;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        # Replace, never append to, whatever the client sent.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Any other name, or a bare IP address: close the connection.
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_reject_handshake on;
    return 444;
}
```

Change `labwarden.example.lan` in all three places. Remove `allow` lines for networks you don't use.

Two lines matter most for security:

- **`X-Forwarded-For $remote_addr`** tells the dashboard the address nginx actually saw. Many guides use `$proxy_add_x_forwarded_for` instead. That *adds* the address to whatever the client sent, so a client could make up its own address.
- **`X-Forwarded-Proto $scheme`** tells the dashboard the request came over HTTPS. The dashboard then marks its sign-in cookie secure and turns on HSTS by itself.

You don't need to add security headers. The dashboard sets its own.

## 3. Add nginx to the Compose project

Create `docker-compose.override.yml` next to `docker-compose.yml`. Compose merges it in automatically. If you already have one, add these parts to it.

```yaml
services:
  nginx:
    image: nginx:1.30.6-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311
    restart: unless-stopped
    depends_on: [labwarden]
    ports:
      - "80:80"
      - "443:443"
    read_only: true
    cap_drop: [ALL]
    # Bind ports 80/443, and start the worker processes as the nginx user.
    cap_add: [NET_BIND_SERVICE, CHOWN, SETUID, SETGID]
    security_opt: [no-new-privileges:true]
    tmpfs: [/var/cache/nginx, /run, /tmp]
    volumes:
      - ./nginx/labwarden.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs/fullchain.pem:/etc/nginx/certs/fullchain.pem:ro
      - ./certs/privkey.pem:/etc/nginx/certs/privkey.pem:ro
    networks:
      default:
        ipv4_address: 172.30.0.10

# A fixed subnet, so nginx's address never changes.
networks:
  default:
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

If `172.30.0.0/24` is already used on your network, pick another private subnet and change the nginx address and `LABWARDEN_TRUSTED_PROXIES` to match.

Only the certificate and key are mounted, not the whole `certs` folder, so a CA key you keep there never reaches the container.

## 4. Tell the dashboard about nginx

Add or change these lines in `.env`:

```bash
# Only reachable from the host itself: everyone else goes through nginx.
LABWARDEN_PORT=127.0.0.1:8080
# nginx's fixed address. Trust nothing else.
LABWARDEN_TRUSTED_PROXIES=172.30.0.10
# The address you open in the browser.
LABWARDEN_PUBLIC_URL=https://labwarden.example.lan
```

Then check the configuration and apply everything. Because the network changes, take the project down first. Plain `down` keeps your data. **Don't add `-v`**, which would delete it.

```bash
docker compose run --rm --no-deps nginx nginx -t
docker compose down
docker compose up -d
docker compose logs nginx
```

## 5. Trust your CA (only with a private CA)

If the certificate comes from your own CA:

- **Browsers:** import the CA certificate (`ca.pem`) into your computer's trust store. On Windows, double-click it and install it into *Trusted Root Certification Authorities*. On macOS, add it to the System keychain in Keychain Access and set it to *Always Trust*. Firefox has its own list under *Settings → Privacy & Security → Certificates*.
- **Agents:** give them the same file with `LABWARDEN_CA_FILE`. See the [Linux agent](agent-linux.md#dashboard-with-a-self-signed-or-private-certificate) and [Docker agent](agent-docker.md#dashboard-with-a-self-signed-or-private-certificate) guides.

## 6. Check it

1. Open `https://labwarden.example.lan` and sign in. The browser should show a valid certificate, without a warning.
2. Sign out, then sign in once with a **wrong** password on purpose.
3. Sign in properly and open **Logs**. You should see `failed admin login from <your computer's address>`.

   If it names `172.30.0.10` instead, the dashboard doesn't trust nginx: check `LABWARDEN_TRUSTED_PROXIES`. If it names `172.30.0.1`, nginx isn't at its fixed address: check the override file.

4. From another machine, `http://<docker-host>:8080` should no longer answer.

Then point your agents at `https://labwarden.example.lan`.

## Renewing the certificate

Replace the two files in `certs`, then reload nginx:

```bash
docker compose exec nginx nginx -s reload
```

If an ACME client renews the certificate for you, have it run that command after each renewal.

## nginx installed on the host instead

If you already run nginx as a system service on the Docker host, use the same `server` blocks with these changes:

- `proxy_pass http://127.0.0.1:8080;` instead of the `resolver`, `set` and `proxy_pass $labwarden` lines
- your own certificate paths
- `listen [::]:80;` and `listen [::]:443 ssl;` as well, if the host uses IPv6

The dashboard then sees nginx's requests as coming from the Compose network's gateway. With the fixed subnet from step 3 (just the `networks:` part), that is `172.30.0.1`, so set `LABWARDEN_TRUSTED_PROXIES=172.30.0.1`.

Be aware of what that means: **every** program on the Docker host that connects to port 8080 appears to come from `172.30.0.1` too, so any of them could fake a client address. Only do this when you are the only one with a shell on that host. Otherwise, run nginx in Compose as shown above.

## Secure setup checklist

- **Overwrite `X-Forwarded-For`** with `$remote_addr`. Never append with `$proxy_add_x_forwarded_for`.
- **Trust only nginx's own address** in `LABWARDEN_TRUSTED_PROXIES`, never a whole subnet, and never the gateway unless nginx runs on the host.
- **Bind the dashboard to localhost** (`LABWARDEN_PORT=127.0.0.1:8080`), so nobody can go around nginx.
- **Set `LABWARDEN_PUBLIC_URL`** to the `https://` address.
- **Don't set `LABWARDEN_COOKIE_SECURE`.** The dashboard marks its cookie secure on its own when nginx tells it the request came over HTTPS.
- **Keep the `allow`/`deny` rules and the catch-all server**, so only your LAN and VPN reach the dashboard, and don't forward ports 80 or 443 to it from your router.
- **Keep TLS modern:** TLS 1.2 and 1.3 only, which is also nginx's default.
- **Protect private keys:** `privkey.pem` owned by root with mode `600`, and your CA key kept out of the Compose folder.
- **Keep nginx hardened and pinned:** read-only filesystem, only the four capabilities it needs, `no-new-privileges`, image pinned by tag and digest. Update the pin on purpose.
- **Never tell agents to skip certificate checks.** Give them `ca.pem` instead.
