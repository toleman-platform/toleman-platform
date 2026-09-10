# Deploying to a free VPS behind Cloudflare

Runs the full stack (Postgres, Redis, backend, celery-worker, frontend) on
one VPS with [Caddy](https://caddyhq.com) as a reverse proxy, fronted by
Cloudflare DNS for `toleman.oasisgoods.store` (frontend) and
`api.toleman.oasisgoods.store` (backend). Everything here is free-tier: the
VPS (Oracle Cloud Always Free), the reverse proxy (Caddy), and the
certificate (Cloudflare Origin CA).

## 1. Create the VPS

[Oracle Cloud's Always Free tier](https://www.oracle.com/cloud/free/) is the
only major free tier that doesn't expire or get billed after a trial period.

1. Sign up (requires a card for identity verification; the Always Free
   resources are never charged).
2. Create a Compute instance:
   - Shape: `VM.Standard.A1.Flex` (Ampere ARM), 2 OCPU / 12GB RAM is plenty.
   - Image: Ubuntu 24.04.
   - Note the public IP.
3. In the instance's VCN Security List (or attach an NSG), allow inbound TCP
   `22` (SSH), `80`, `443`. Leave everything else closed -- `5432`, `6379`,
   `8000`, `3000` never need to be reachable from the internet.
4. Because this is the ARM shape, the published `edge` GHCR images (amd64
   only) won't run here -- the steps below build from source instead, which
   the repo already supports via `docker compose up --build`.

## 2. Install Docker

SSH in, then:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
```

## 3. Cloudflare: DNS + origin certificate

In the Cloudflare dashboard for the `oasisgoods.store` zone:

1. **DNS -> Add record**, twice, both proxied (orange cloud):
   - `A` record `toleman` -> the VPS public IP
   - `A` record `api.toleman` -> the VPS public IP
2. **SSL/TLS -> Overview**: set the encryption mode to **Full (strict)**.
3. **SSL/TLS -> Origin Server -> Create Certificate**: accept the defaults
   (covers `*.oasisgoods.store` and `oasisgoods.store`, 15-year validity).
   Cloudflare shows you a certificate and a private key once -- save both.

On the VPS:

```bash
mkdir -p ~/toleman-platform/deploy/certs
# paste the certificate Cloudflare showed you:
nano ~/toleman-platform/deploy/certs/origin.pem
# paste the private key:
nano ~/toleman-platform/deploy/certs/origin-key.pem
```

This is why Caddy is configured to use a static certificate
(`deploy/Caddyfile`) instead of its usual automatic Let's Encrypt: Let's
Encrypt's HTTP-01 challenge can't reach an origin hidden behind Cloudflare's
proxy, but a Cloudflare Origin CA certificate is exactly what "Full
(strict)" mode expects.

## 4. Deploy

```bash
git clone https://github.com/toleman-platform/toleman-platform.git
cd toleman-platform
cp deploy/.env.prod.example .env
nano .env   # fill in POSTGRES_PASSWORD, WORKSPACE_API_KEY, SESSION_SECRET,
            # ADMIN_EMAIL/PASSWORD, PLATFORM_ENCRYPTION_KEY (see comments
            # in the file for how to generate each)

docker compose -f docker-compose.yml -f deploy/docker-compose.prod.yml up -d --build
```

First boot runs Alembic migrations and seeds the admin account (see
`docker-compose.yml`'s comments on `init_db()`). Watch it come up with
`docker compose logs -f backend`.

## 5. Verify

- `https://toleman.oasisgoods.store` loads the frontend.
- `https://api.toleman.oasisgoods.store/health` returns healthy.
- Log in with the `ADMIN_EMAIL` / `ADMIN_PASSWORD` from your `.env`.

## 6. Updating

```bash
cd ~/toleman-platform
./scripts/backup-postgres.sh
git pull
docker compose -f docker-compose.yml -f deploy/docker-compose.prod.yml up -d --build
```

## Optional hardening: Cloudflare Tunnel instead of open ports

Once this is working, `80`/`443` can be closed entirely and replaced with a
`cloudflared` tunnel container, so the VPS has no public inbound ports at
all. Not required for the free-tier goal here, but worth doing later if you
want fewer things exposed to the internet -- ask and I'll wire it up.
