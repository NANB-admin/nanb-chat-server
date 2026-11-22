# NANb Chat Server

The backend for [NANb Chat](https://github.com/NANB-admin/nanb-chat-client), an
end-to-end encrypted messenger for Android, iOS and the web.

The server only ever sees ciphertext. It stores accounts and public keys, routes
encrypted envelopes between devices, hands out short-lived media upload and
download URLs for encrypted blobs, and relays push notifications. Message
content is encrypted on the devices with MLS (RFC 9420) and the server cannot
read it.

- Website: <https://nanb.us>
- Client: <https://github.com/NANB-admin/nanb-chat-client> (GPL-3.0-only)
- Licence: AGPL-3.0-only (see [LICENSE](LICENSE), [NOTICE](NOTICE) and
  [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md))

## Why this is public

So the service is not a single point of failure. If the server run by NANB ever
goes away, anyone can run their own from this code, and everyone who wants to
follow just changes the server URL in the app (**Settings > Network > Server
URL**). Start with **[SELF_HOSTING.md](SELF_HOSTING.md)**.

The AGPL means that if you run a modified version of this server for other
people, you must offer those people the source of your modified version (a link
to a public fork is enough). Running it unmodified requires nothing beyond
keeping the licence notices.

## Source for each release

Every release is tagged `server-<date or number>`. The tag holds exactly the
source that deployment was built from.

## Quick start (local development)

Requirements: Go 1.26+, PostgreSQL 14+, and the
[`migrate`](https://github.com/golang-migrate/migrate) CLI.

```
export NANB_PG_CONN="postgres://USER:PASS@localhost:5432/DB?sslmode=disable"
export NANB_DEV_MODE=true          # ephemeral signing key, local use only
make migrate-up                    # create the schema
make run                           # listens on :8080
curl localhost:8080/health         # -> ok
```

To run it for real, use the Docker stack in [SELF_HOSTING.md](SELF_HOSTING.md).

## Testing

```
make test           # unit tests; every third-party service is mocked
make cover
```

No database or cloud account is needed to run the tests.

## Configuration

Everything is an environment variable. [`.env.example`](.env.example) lists all
of them with explanations. The ones you will touch first:

| Variable | Required | Purpose |
|---|---|---|
| `NANB_PG_CONN` | yes | PostgreSQL connection string |
| `NANB_JWT_PRIV_KEY_B64` | yes (prod) | Ed25519 session-signing key; make one with `go run ./cmd/genkey` |
| `NANB_LISTEN_ADDR` | no | HTTP listen address, default `:8080` |
| `NANB_TOR_LISTEN_ADDR` | no | Onion-service listener, unset = off |
| `NANB_S3_BUCKET`, `NANB_AWS_REGION` | for media | Encrypted media storage |
| `NANB_FCM_SERVICE_ACCOUNT_PATH` | for Android push | Firebase service account |
| `NANB_APNS_*` | for iOS push/CallKit | Apple push key |
| `NANB_TURN_AUTH_SECRET`, `NANB_TURN_URLS` | for calls | TURN relay |
| `NANB_GIPHY_API_KEY` | for GIFs | GIF search proxy |

## Layout

```
cmd/server/        entry point with graceful shutdown
cmd/genkey/        prints a fresh NANB_JWT_PRIV_KEY_B64
internal/
  identity/        accounts, devices, login challenge/response
  keypackages/     MLS key packages
  delivery/        encrypted envelope routing, WebSocket hub
  media/           encrypted media metadata + signed URLs
  push/            APNs + FCM registry and dispatch
  turn/            short-lived TURN credentials for calls
  gif/             GIF search proxy
  moderation/      user reports
  retention/       worker that deletes expired media and envelopes
  auth/            JWT bearer-token middleware
  ratelimit/       request budgets
  crypto/ proto/ storage/ httputil/ apierr/
deploy/            Caddy, Tor, coturn and systemd configs
migrations/        golang-migrate SQL files (the whole schema)
```

## Contributing

Issues and pull requests are welcome. By submitting a contribution you agree to
license it under AGPL-3.0-only. Please sign off your commits (`git commit -s`).

## Security

Please report vulnerabilities privately to contact@nanb.us rather than opening
a public issue.
