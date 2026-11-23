# Running your own NANb Chat server

This guide takes you from an empty Linux machine to a working server that the
NANb Chat app can talk to. You need basic comfort with a terminal and Docker.
Plan on about 30 minutes, most of it waiting for DNS.

## What you are running

| Piece | Needed? | What it does |
|---|---|---|
| **Server** (this repo) | yes | The API and WebSocket: accounts, message routing, key packages |
| **PostgreSQL** | yes | The only database. Bundled in the Docker stack |
| **Caddy** | yes (for HTTPS) | Reverse proxy that gets a free TLS certificate |
| **Tor** | optional | Lets people reach your server as an `.onion` address |
| **Media storage (S3)** | optional | Photos, files, voice notes. Without it, text and calls still work |
| **Push (FCM / APNs)** | optional | Notifications when the app is closed |
| **TURN relay (coturn)** | optional | Needed for voice calls across NATs |
| **GIF search** | optional | Needs a Giphy API key |

The minimum viable server is Server + PostgreSQL + Caddy, which the compose file
brings up for you.

## 1. Requirements

- A Linux machine with a public IP (1 vCPU / 1 GB RAM is enough for a small
  community) and ports **80** and **443** open.
- A domain name, with an `A` record (e.g. `chat.example.org`) pointing at it.
- Docker with the Compose plugin.

## 2. Get the code

```
git clone https://github.com/NANB-admin/nanb-chat-server.git
cd nanb-chat-server
```

## 3. Configure

```
cp deploy/compose.env.example .env
```

Edit `.env`:

1. `NANB_DOMAIN`: your domain.
2. `POSTGRES_PASSWORD` and the same password inside `NANB_PG_CONN`. Use a long
   random string (`openssl rand -hex 24`).
3. `NANB_JWT_PRIV_KEY_B64`: generate it once and keep it. If it changes, every
   user is signed out.
   ```
   docker run --rm -v "$PWD":/src -w /src golang:1.26-alpine go run ./cmd/genkey
   ```

## 4. Start it

```
docker compose up -d --build
docker compose logs -f server
```

Startup order is automatic: Postgres starts, the `migrate` container creates the
whole database schema from `migrations/`, then the server starts. When it is up,
Caddy fetches your certificate on first request.

Check it:

```
curl https://chat.example.org/health      # -> ok
```

## 5. The database

There is nothing to set up by hand. The compose file runs Postgres 16 in a
container with its data in the `postgres_data` volume, and the `migrate` service
applies the schema on every `docker compose up`. It is safe to repeat: it does
nothing if the schema is current, and it applies only new migrations after you
pull an update.

**Back it up.** Everything users have (accounts, public keys, queued messages)
lives in that volume:

```
docker compose exec postgres pg_dump -U nanb nanb | gzip > nanb-$(date +%F).sql.gz
```

**Using your own Postgres** (managed or existing): delete the `postgres`
service from `docker-compose.yml`, remove it from `migrate`'s `depends_on`, and
set `NANB_PG_CONN` to your database (`sslmode=require` for a remote one). You
need PostgreSQL 14 or newer and a database the user can create schemas in.

**Without Docker:** install the
[`migrate`](https://github.com/golang-migrate/migrate) CLI and run
`NANB_PG_CONN=... make migrate-up`, then build with `make build` and run
`bin/nanb-server` (a sample unit is in `deploy/systemd/`).

## 6. Point the app at your server

In the NANb Chat app: **Settings > Network > Server URL**, enter
`https://chat.example.org`, and save. New accounts are created on your server.

Important: accounts live on one server. People on your server and people on the
official server are separate; they cannot message each other. To move a
community, everyone creates (or restores) an account on the new server.

## 7. Optional features

Set these in `.env`, then `docker compose up -d`.

- **Onion service.** Keep `NANB_TOR_LISTEN_ADDR` and the `tor` service. Your
  address is `docker compose exec tor cat /var/lib/tor/nanb/hostname`. Back up
  the `tor_data` volume; it holds the key that *is* your `.onion` name.
- **Media.** The server stores encrypted blobs in an AWS S3 bucket. Create a
  bucket, give the machine credentials that can read/write it (an IAM role on
  EC2, or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env`), and set
  `NANB_AWS_REGION` and `NANB_S3_BUCKET`. The bucket must stay private; the
  server hands out short-lived signed URLs. Objects are encrypted before they
  are uploaded, so the bucket never holds plaintext.
  `NANB_CDN_*` adds optional CloudFront signed URLs.

  **Known limitation: media currently needs AWS S3.** The server talks to
  Amazon's S3 only; there is no setting yet for a custom endpoint, so
  S3-compatible services (MinIO, Cloudflare R2, Backblaze B2, Wasabi) do not
  work today. If you are not on AWS you can still run everything else, and
  text messages and calls work normally; sending photos, files and voice notes
  will fail. Support for a custom endpoint is a planned improvement
  (contributions welcome). When it lands, remember that: the endpoint must be
  HTTPS (signed URLs are bearer links), the key should be scoped to the one
  private bucket, and object versioning should be off so deletes are real.
  Files are encrypted on the phone before upload, so the storage provider only
  ever sees ciphertext, sizes and timing.
- **Push notifications.** Create a Firebase project, download its service-account
  JSON to `secrets/firebase.json`, and set `NANB_FCM_SERVICE_ACCOUNT_PATH`. iOS
  CallKit ringing also needs an Apple push key (`NANB_APNS_*`). Note that push
  only works with an app build that is signed for *your* Firebase/Apple
  project; the official store apps are tied to the official one. Without push,
  the app still receives messages while it is open.
- **Voice calls.** Run [coturn](https://github.com/coturn/coturn) using
  `deploy/coturn/turnserver.conf` as a starting point, then set
  `NANB_TURN_AUTH_SECRET` (the same value as coturn's `static-auth-secret`) and
  `NANB_TURN_URLS`, e.g.
  `turns:turn.example.org:443?transport=tcp,turn:turn.example.org:3478?transport=udp`.
  Calls are relay-only by design, so without TURN they will not connect.
- **GIF search.** Set `NANB_GIPHY_API_KEY`. Unset, the GIF tab shows an error.
- **Abuse reports by email.** Set `NANB_SMTP_*` and `NANB_REPORT_EMAIL_TO`.
- **Web client.** To serve the web app from your own domain, list its origin in
  `NANB_WEB_ORIGINS` so the browser may open the WebSocket.

Everything optional that is not configured is simply off; the server logs a
`WARN` line at startup saying which.

## 8. Updating

```
git pull
docker compose up -d --build
```

New migrations apply automatically. Back up the database first.

## 9. Privacy hygiene for operators

The server was built to know as little as possible, so please do not undo that:

- Keep the Caddy access log as shipped (no IPs, no URLs).
- Do not log request bodies.
- Retention is capped in code (envelopes and media at most 30 days); you may
  shorten it with `NANB_ENVELOPE_RETENTION_DAYS` and `NANB_MEDIA_RETENTION_DAYS`.
- If you modify the server and run it for others, the AGPL requires you to make
  your modified source available to them.

## Troubleshooting

- **`docker compose` says a variable is not set**: you skipped a required line in
  `.env` (`NANB_DOMAIN`, `POSTGRES_PASSWORD`).
- **Certificate never arrives**: DNS is not pointing at the machine yet, or
  ports 80/443 are blocked. `docker compose logs caddy`.
- **Server exits with `NANB_JWT_PRIV_KEY_B64 is required`**: generate and set the
  signing key (step 3).
- **App cannot connect**: the URL must start with `https://` and have no trailing
  path. Test `/health` in a browser first.
