package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/gif"
	"github.com/nanb/nanb-server/internal/httputil"
	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/keypackages"
	"github.com/nanb/nanb-server/internal/media"
	"github.com/nanb/nanb-server/internal/moderation"
	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/push"
	"github.com/nanb/nanb-server/internal/retention"
	"github.com/nanb/nanb-server/internal/storage"
	"github.com/nanb/nanb-server/internal/turn"
)

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type uuidGen struct{}

func (uuidGen) Next() string { return uuid.NewString() }

// idLookupAdapter converts identity.Service.LookupAccount (which returns a
// full Account record + may surface APIError with ErrCodeAccountNotFound)
// into the slim keypackages.AccountLookup signature. Avoids a direct
// identity→keypackages import dependency.
type idLookupAdapter struct{ svc *identity.Service }

func (a idLookupAdapter) AccountIDByUsername(ctx context.Context, username string) (string, error) {
	acc, err := a.svc.LookupAccount(ctx, username)
	if err != nil {
		var apiErr proto.APIError
		if errors.As(err, &apiErr) && apiErr.Code == proto.ErrCodeAccountNotFound {
			return "", keypackages.ErrAccountNotFound
		}
		return "", err
	}
	return acc.AccountID, nil
}

// recipientResolverAdapter exposes the identity store's device→account
// resolution as delivery.RecipientResolver: a device is "live" when it is
// unrevoked and its account is not deleted. Lets SubmitMessage reject
// sends addressed to deleted accounts instead of black-holing them.
type recipientResolverAdapter struct{ store *identity.StorePostgres }

func (r recipientResolverAdapter) RecipientLive(ctx context.Context, deviceID string) (bool, error) {
	_, live, err := r.AccountForDevice(ctx, deviceID)
	return live, err
}

// AccountForDevice returns the device's owning account id (server-authoritative),
// so SubmitMessage can bind recipient_account_id to the real target rather than
// trusting the client's value. live==false (accountID=="") means the device is
// revoked or its account deleted.
func (r recipientResolverAdapter) AccountForDevice(ctx context.Context, deviceID string) (string, bool, error) {
	acc, live, _, err := r.AccountForDeviceExpiry(ctx, deviceID)
	return acc, live, err
}

// AccountForDeviceExpiry is AccountForDevice plus the device's own expires_at
// (nil = never), implementing delivery.ExpiringRecipientResolver so the
// liveness cache can't keep an expired web device live. Liveness itself comes
// from the store's active-device definition (not revoked AND not expired).
func (r recipientResolverAdapter) AccountForDeviceExpiry(ctx context.Context, deviceID string) (string, bool, *time.Time, error) {
	acc, err := r.store.GetAccountByDeviceID(ctx, deviceID)
	if errors.Is(err, identity.ErrNotFound) {
		return "", false, nil, nil
	}
	if err != nil {
		return "", false, nil, err
	}
	dev, err := r.store.GetActiveDeviceByID(ctx, deviceID)
	if errors.Is(err, identity.ErrNotFound) {
		// Raced a revoke/expiry between the two reads: treat as not live.
		return "", false, nil, nil
	}
	if err != nil {
		return "", false, nil, err
	}
	return acc.AccountID, true, dev.ExpiresAt, nil
}

var errInvalidJWTKey = errors.New("NANB_JWT_PRIV_KEY_B64: invalid Ed25519 private key length")

// defaultInsecurePGConn is the LOCAL-DEV Postgres connection used when
// NANB_PG_CONN is unset: a hardcoded password with TLS disabled. main() warns
// loudly when it is used outside dev mode (a forgotten NANB_PG_CONN in prod).
const defaultInsecurePGConn = "postgres://nanbchatapp:password@localhost:5432/nanb_chat_app?sslmode=disable"

// errMissingJWTKeyProd is returned when the signing key is unset and the process
// is NOT in dev mode. Failing closed here prevents a misconfigured prod deploy
// from silently minting a fresh ephemeral key on every restart — which would
// invalidate every live session (all JWTs signed by the previous key).
var errMissingJWTKeyProd = errors.New("NANB_JWT_PRIV_KEY_B64 is required (set NANB_DEV_MODE=true only for local development)")

func main() {
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()

	jwtKeyB64 := os.Getenv("NANB_JWT_PRIV_KEY_B64")
	// Dev mode gates the ephemeral-JWT-key convenience AND the insecure Postgres
	// default below: a prod deploy that forgot either must not silently run on a
	// throwaway config.
	devMode := os.Getenv("NANB_DEV_MODE") == "true"

	// The default conn is a LOCAL-DEV convenience (hardcoded password,
	// sslmode=disable). Using it outside dev mode almost always means
	// NANB_PG_CONN was forgotten — warn loudly. (Unlike the JWT key, this only
	// warns: a wrong/default conn already fails at pool connect below, so the
	// warning just makes the misconfig obvious instead of a confusing error.)
	connStr := os.Getenv("NANB_PG_CONN")
	if connStr == "" {
		connStr = defaultInsecurePGConn
		if !devMode {
			log.Printf("WARNING: NANB_PG_CONN unset — using the INSECURE local-dev " +
				"default (hardcoded password, sslmode=disable). Set NANB_PG_CONN in " +
				"production, or NANB_DEV_MODE=true to silence this for local dev.")
		}
	}

	pool, err := storage.NewPool(rootCtx, connStr)
	if err != nil {
		log.Fatalf("postgres connect: %v", err)
	}
	defer pool.Close()

	jwtPriv, err := loadOrGenerateJWTKey(jwtKeyB64, devMode)
	if err != nil {
		log.Fatalf("jwt key: %v", err)
	}
	jwtPub := jwtPriv.Public().(ed25519.PublicKey)

	cfg := loadConfig()

	// WebSocket hub — created before identity so linking a device can push a
	// devices_changed signal to the account's already-connected devices.
	hub := delivery.NewHub()
	// Closes a revoked device's open socket; its liveness cache is attached
	// once that exists (below).
	revokedKicker := &delivery.RevokedDeviceKicker{Hub: hub}

	// Identity
	idStore := identity.NewStorePostgres(pool)
	idSvc := identity.NewService(identity.ServiceDeps{
		Store:              idStore,
		Clock:              realClock{},
		IDGen:              uuidGen{},
		JWTSignKey:         jwtPriv,
		JWTLifetime:        cfg.JWTLifetime,
		ChallengeLifetime:  cfg.ChallengeLifetime,
		KeyPackageLifetime: cfg.KeyPackageLifetime,
		WebDeviceLifetime:  cfg.WebDeviceLifetime,
		DevicesChanged:     delivery.DevicesChangedBroadcaster{Hub: hub},
		DevicesRevoked:     revokedKicker,
	})
	idHandlers := identity.NewHandlers(idSvc)

	// KeyPackages (MLS — Plan A)
	kpStore := keypackages.NewStorePostgres(pool)
	kpSvc := keypackages.NewService(keypackages.ServiceDeps{
		Store:         kpStore,
		AccountLookup: idLookupAdapter{svc: idSvc},
		LowWaterMark:  10,
		MaxPerBatch:   200,
		MaxBlobSize:   8 * 1024,
		// One requester account may claim only so many of ONE other account's
		// single-use packages per window (own packages are never limited).
		ClaimQuota: keypackages.NewPairClaimQuota(
			keypackages.DefaultClaimQuotaBurst, keypackages.DefaultClaimQuotaEvery, nil),
		Published: siblingPublishNotifier{
			devices: idStore,
			changed: delivery.DevicesChangedBroadcaster{Hub: hub},
		},
	})
	kpHandlers := keypackages.NewHandlers(kpSvc)

	// Media (S3 + service + handlers)
	mediaStore := media.NewStorePostgres(pool)
	s3 := buildS3Client(rootCtx)
	mediaSvc := media.NewService(media.ServiceDeps{
		Store:            mediaStore,
		S3:               s3,
		Clock:            realClock{},
		IDGen:            uuidGen{},
		MaxSizeBytes:     cfg.MediaMaxSizeBytes,
		DefaultRetention: cfg.MediaRetention,
		PresignTTL:       cfg.PresignTTL,
		CDN:              buildCDNSigner(),
	})
	mediaHandlers := media.NewHandlers(mediaSvc)

	// Push (composite client + service + handlers). A wakeup whose first send
	// fails lands in the outbox and is retried by pushRetryWorker below, so one
	// transient FCM/APNs fault no longer costs the recipient a notification.
	pushStore := push.NewStorePostgres(pool)
	pushClient := buildPushClient(rootCtx)
	pushOutbox := push.NewOutboxPostgres(pool)
	pushSvc := push.NewService(push.ServiceDeps{
		Store:  pushStore,
		Client: pushClient,
		Outbox: pushOutbox,
		// iOS CallKit ring over PushKit. nil when APNs isn't configured, in which
		// case a call falls back to the ordinary alert push everywhere.
		VoipStore:  push.NewVoipStorePostgres(pool),
		VoipClient: buildVoipPushClient(),
		// Off until every iPhone runs a build that handles a VoIP cancel (see
		// push.ServiceDeps.VoipCancelEnabled).
		VoipCancelEnabled: os.Getenv("NANB_VOIP_CANCEL") == "true",
	})
	pushHandlers := push.NewHandlers(pushSvc)

	// GIF proxy (Giphy) — keeps the provider API key server-side (off the mobile
	// binary) and GIF search terms off a third party at the user's IP. Optional:
	// with no key the /gifs/* endpoints return 503 and the client's GIF tab errors.
	gifSvc := gif.NewService(gif.ServiceDeps{APIKey: os.Getenv("NANB_GIPHY_API_KEY")})
	if gifSvc.Enabled() {
		log.Println("gif: Giphy proxy enabled")
	} else {
		log.Println("WARN: NANB_GIPHY_API_KEY unset; GIF proxy disabled (clients get 503)")
	}
	gifHandlers := gif.NewHandlers(gifSvc)

	// TURN credentials for 1:1 calls (coturn use-auth-secret). Optional: with no
	// secret/URLs the endpoint returns 503 and calls fall back to direct/STUN
	// candidates (so they only work on cooperative NATs until coturn is up).
	turnHandlers := turn.NewHandlers(turn.Config{
		Secret: os.Getenv("NANB_TURN_AUTH_SECRET"),
		URLs:   splitCSV(os.Getenv("NANB_TURN_URLS")),
		// Optional second relay (Frankfurt) for viewers nearer to it; same secret.
		URLsEurope: splitCSV(os.Getenv("NANB_TURN_URLS_EU")),
		TTL:    cfg.TurnTTL,
	})
	if turnHandlers.Enabled() {
		log.Println("turn: credential endpoint enabled")
	} else {
		log.Println("WARN: NANB_TURN_AUTH_SECRET/NANB_TURN_URLS unset; TURN disabled (calls can't traverse NAT)")
	}

	// Delivery
	delStore := delivery.NewStorePostgres(pool)
	// Short-TTL cache over the device-liveness / account lookup so repeat sends in
	// a conversation skip the per-send DB reads (liveness changes only on
	// revoke/delete). Shared with the REST auth middleware (below) so a revoked
	// device is kicked off REST too, not just the WS handshake.
	resolver := delivery.NewCachedResolver(
		recipientResolverAdapter{store: idStore}, 30*time.Second)
	if f, ok := resolver.(delivery.LivenessForgetter); ok {
		revokedKicker.Liveness = f
	}
	delSvc := delivery.NewService(delivery.ServiceDeps{
		Store:             delStore,
		Clock:             realClock{},
		IDGen:             uuidGen{},
		Hub:               hub,
		Pusher:            pushSvc,
		Recipients:        resolver,
		EnvelopeRetention: cfg.EnvelopeRetention,
		ConversationCap:   cfg.ConversationCap,
		MaxCiphertextSize: cfg.MessageMaxSizeBytes,
		// Rate-limits only the call RING (push_kind "call"), never message pushes.
		CallPushGate: delivery.NewCallPushGate(nil),
	})

	// REST active-device gate: reject a revoked device (recovery-phrase takeover)
	// before its JWT expires, mirroring the WS handshake. Fails OPEN on a
	// transient backend error so a storage blip doesn't lock the whole API out —
	// the JWT signature + expiry remain the primary gate (see auth.DeviceActiveFunc).
	deviceActive := func(ctx context.Context, deviceID string) bool {
		live, err := resolver.RecipientLive(ctx, deviceID)
		if err != nil {
			return true
		}
		return live
	}
	delHandlers := delivery.NewHandlers(delSvc, hub)
	// Typing frames: sender liveness + the 1:1 membership check go through the
	// same short-TTL cached resolver, not a DB read per frame.
	delHandlers.SetTypingResolver(resolver)
	// Kick a revoked device at the WS handshake (recovery-phrase takeover on
	// another phone): a one-shot active-device lookup per connection.
	delHandlers.SetDeviceValidator(func(ctx context.Context, deviceID string) bool {
		_, err := idStore.GetActiveDeviceByID(ctx, deviceID)
		return err == nil
	})
	// Sealed-sender Phase 2: authorize unauthenticated sealed sends by verifying
	// the presented UAK against the recipient's stored commitment (identity svc).
	delHandlers.SetAccessKeyVerifier(idSvc)
	// Browser (web client) support is OFF unless NANB_WEB_ORIGINS lists the
	// origin(s) the web app is served from, e.g. "https://chat.example.org". It
	// enables CORS for those origins, the /ws/ticket exchange and the WebSocket
	// Origin allow-list; native clients are unaffected either way.
	webOrigins := splitCSV(os.Getenv("NANB_WEB_ORIGINS"))
	if len(webOrigins) > 0 {
		delHandlers.SetWSTickets(delivery.NewWSTicketStore(delivery.WSTicketLifetime, time.Now))
		delHandlers.SetWebOrigins(webOrigins)
	}

	// Moderation (user reports). Reports are ALWAYS stored in the DB moderation
	// queue (satisfies the app stores' report-content requirement); email
	// notification is opt-in via NANB_SMTP_* (see buildReportNotifier).
	modStore := moderation.NewStorePostgres(pool)
	modSvc := moderation.NewService(moderation.ServiceDeps{
		Store:    modStore,
		Notifier: buildReportNotifier(),
		Clock:    realClock{},
		IDGen:    uuidGen{},
	})
	modHandlers := moderation.NewHandlers(modSvc)

	// Retention worker — sweeps expired media (S3 + metadata) and expired
	// message envelopes on the same tick.
	retWorker := retention.NewWorker(mediaSvc, cfg.RetentionBatch)
	retWorker.AddCleaner("envelope", delSvc)
	go retWorker.Run(rootCtx, cfg.RetentionInterval)

	// Push retry worker — re-sends wakeups whose inline attempt failed, and
	// prunes tokens the provider reports dead. Ticks well under the shortest
	// backoff step (15s) so a due retry isn't held up by the sweep interval.
	// The consumed-checker keeps a retry from buzzing about a message the
	// recipient has since pulled — a retry can fire ~21 minutes after the
	// original send, long enough for them to have opened the app and read it.
	pushRetryWorker := push.NewRetryWorker(pushOutbox, pushStore, pushClient).
		WithConsumedChecker(delSvc)
	go pushRetryWorker.Run(rootCtx, 10*time.Second)

	clientIPs := httputil.NewClientIPResolver(clientIPConfigFromEnv())
	r := buildRouter(jwtPub, deviceActive, idHandlers, delHandlers, mediaHandlers, pushHandlers, kpHandlers, gifHandlers, turnHandlers, modHandlers, webOrigins, clientIPs)

	clearnetAddr := envOrDefault("NANB_LISTEN_ADDR", ":8080")
	torAddr := os.Getenv("NANB_TOR_LISTEN_ADDR")

	servers := []*http.Server{newServer(clearnetAddr, r)}
	if torAddr != "" {
		// Everything on the onion listener is marked as such: it all arrives
		// from the local Tor daemon, so it shares the onion rate-limit key and
		// no forwarded header on it is ever believed.
		servers = append(servers, newServer(torAddr, httputil.MarkOnion(r)))
	}

	// Start each server.
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			log.Printf("nanb-server listening on %s", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("listen %s: %v", srv.Addr, err)
			}
		}(s)
	}

	// Wait for SIGTERM/SIGINT.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Println("nanb-server: shutdown signal received")

	cancelRoot() // stops retention worker

	// Graceful HTTP shutdown with 30s grace.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown %s: %v", s.Addr, err)
		}
	}
	wg.Wait()
	log.Println("nanb-server: stopped")
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}
}

// Server-wide connection timeouts (see newServer).
//
// Read/Write cover the WHOLE request body read / response write, so they are
// sized for the slowest legitimate small call: a 4 MiB message submit or a
// catch-up page over a Tor circuit (~50 KB/s => ~80s). 2 minutes clears that
// while still killing slowloris-style trickle bodies, which ReadHeaderTimeout
// alone does not. Long-lived and bulk routes opt out individually:
//   - /ws is HIJACKED by coder/websocket on upgrade, and net/http clears the
//     connection deadlines when a connection is hijacked, so the socket is
//     not subject to Read/WriteTimeout (the library manages its own pings).
//   - /media/upload, /media/stream and /gifs/media stream large bodies and
//     extend their own deadlines with httputil.ExtendDeadlines.
//
// IdleTimeout is deliberately above CloudFront's origin keep-alive (<=60s) so
// the edge, not this server, is the side that closes an idle pooled connection.
const (
	serverReadTimeout  = 2 * time.Minute
	serverWriteTimeout = 2 * time.Minute
	serverIdleTimeout  = 2 * time.Minute

	// bulkTransferDeadline is the per-request deadline for streaming media and
	// GIF proxy routes: 100 MiB at ~50 KB/s over Tor is ~35 minutes worst case,
	// so 15 minutes covers realistic mobile/Tor throughput without leaving a
	// connection open indefinitely.
	bulkTransferDeadline = 15 * time.Minute
)

// Per-endpoint request-body caps (http.MaxBytesReader). The default covers small
// token/session/control/ack bodies; the larger caps admit key-package batches
// (keypackages MaxPerBatch × MaxBlobSize, base64-expanded) and message submits
// (ciphertext up to the configured max, base64-expanded). Coarse outer bounds —
// the service layer still enforces the exact ciphertext / key-package sizes.
const (
	maxBodyDefault     = 256 << 10 // 256 KiB
	maxBodyKeyPackages = 4 << 20   // 4 MiB
	maxBodyMessage     = 4 << 20   // 4 MiB
)

// sealedAccessLog logs the sealed submission (method / path / status / latency)
// but DELIBERATELY omits the remote address, so the UNAUTHENTICATED sender's
// source IP is never tied to the deposit timestamp — that pairing would
// undermine sealed-sender off the Tor happy-path. RealIP must NOT run upstream
// of this route (it would repopulate RemoteAddr from X-Forwarded-For). The
// client key resolved at the top of the router is used only, in memory, to
// throttle sources that keep presenting WRONG access keys; it is never logged.
func sealedAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			log.Printf("sealed %s %s -> %d in %s", r.Method, r.URL.Path, ww.Status(), time.Since(start))
		}()
		next.ServeHTTP(ww, r)
	})
}

func buildRouter(
	jwtPub ed25519.PublicKey,
	deviceActive auth.DeviceActiveFunc,
	idH *identity.Handlers,
	delH *delivery.Handlers,
	mediaH *media.Handlers,
	pushH *push.Handlers,
	kpH *keypackages.Handlers,
	gifH *gif.Handlers,
	turnH *turn.Handlers,
	modH *moderation.Handlers,
	webOrigins []string,
	clientIPs *httputil.ClientIPResolver,
) http.Handler {
	r := chi.NewRouter()
	// FIRST: resolve each request's client key from the RAW peer address,
	// before middleware.RealIP (below, per group) rewrites RemoteAddr from
	// headers a client can set. nil (tests) → keys fall back to the peer.
	if clientIPs != nil {
		r.Use(clientIPs.Middleware)
	}
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	// No-op unless webOrigins is non-empty (see httputil.CORS).
	r.Use(httputil.CORS(webOrigins))

	// Per-client budgets for the unauthenticated identity endpoints (see
	// rate_limits.go). Built once per router so the three identity-write
	// routes share one limiter (one budget per client across them).
	identityWriteLim := httputil.NewClientRateLimiter(identityWriteLimits(), nil).Middleware
	usernameLookupLim := httputil.NewClientRateLimiter(usernameLookupLimits(), nil).Middleware

	// The WebSocket upgrade is a long-lived connection and MUST be registered
	// OUTSIDE the 30s request timeout below — that timeout cancels the request
	// context at 30s, which was tearing down every WS connection at exactly 30s
	// and forcing constant reconnects. It gets the standard access log (route pattern only, see httputil.AccessLog).
	r.Group(func(r chi.Router) {
		r.Use(middleware.RealIP)
		r.Use(httputil.AccessLog)
		r.Get("/ws", delH.HandleWS(jwtPub))
	})

	// All REST routes share a 30s request timeout.
	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(30 * time.Second))

		// Sealed-sender Phase 2 (unidentified access): the sealed send is
		// DELIBERATELY unauthenticated — it carries no JWT so the server never
		// learns the sender. Authorization is the recipient's UAK, verified inside
		// the handler; the server stores the envelope with no sender. It is
		// registered in its OWN group so it gets neither RealIP nor the IP access
		// log — see sealedAccessLog.
		r.Group(func(r chi.Router) {
			r.Use(sealedAccessLog)
			r.With(httputil.MaxBytes(maxBodyMessage)).Post("/messages/sealed", delH.PostSealedMessage)
		})

		// Every other route: standard access log (no paths/addresses) + per-endpoint body caps.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RealIP)
			r.Use(httputil.AccessLog)

			r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})

			r.With(identityWriteLim, httputil.MaxBytes(maxBodyKeyPackages)).Post("/accounts", idH.PostAccount)
			// Pre-signup availability check — must be reachable without a session,
			// so it carries its own per-client limit to bound bulk enumeration.
			r.With(usernameLookupLim).Get("/usernames/{username}", idH.GetUsernameAvailability)
			r.With(identityWriteLim, httputil.MaxBytes(maxBodyDefault)).Post("/sessions/challenge", idH.PostChallenge)
			r.With(httputil.MaxBytes(maxBodyDefault)).Post("/sessions", idH.PostSession)
			r.With(identityWriteLim, httputil.MaxBytes(maxBodyDefault)).Post("/sessions/restore/challenge", idH.PostRestoreChallenge)
			r.With(httputil.MaxBytes(maxBodyDefault)).Post("/sessions/restore", idH.PostRestoreSession)
			// Link-status poll for a freshly-keyed device that has no session yet;
			// keyed by its own high-entropy pub key, so it must stay unauthenticated.
			r.Get("/devices/pending/{device_pub_key}", idH.GetPendingDevice)

			r.Group(func(r chi.Router) {
				r.Use(auth.RequireJWTWithDevice(jwtPub, deviceActive))

				r.Get("/accounts/by-id/{account_id}", idH.GetAccountByID)
				r.Get("/accounts/{username}", idH.GetAccount)
				r.With(httputil.MaxBytes(maxBodyDefault)).Patch("/accounts/me", idH.PatchMe)
				r.Delete("/accounts/me", idH.DeleteMyAccount)
				r.Get("/devices", idH.GetDevices)
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/devices/me/capabilities", idH.PostMyDeviceCapabilities)
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/accounts/me/access-key", idH.PostMyAccessKey)
				r.With(httputil.MaxBytes(maxBodyKeyPackages)).Post("/devices/link", idH.PostDeviceLink)
				r.Get("/devices/{device_id}/account", idH.GetAccountByDevice)
				// One-time ticket a browser exchanges for a WebSocket (see delivery.WSTicketStore).
				r.Post("/ws/ticket", delH.PostWSTicket)
				r.Delete("/devices/{device_id}", idH.RevokeDevice)

				r.With(httputil.MaxBytes(maxBodyMessage)).Post("/messages", delH.PostMessage)
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/messages/catchup", delH.PostCatchup)
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/messages/ack", delH.PostAck)
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/messages/received", delH.PostReceived)
				r.Get("/messages/by-id/{envelope_id}", delH.GetEnvelopeByID)

				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/media/init", mediaH.PostInitUpload)
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/media/get", mediaH.PostGetMedia)
				// Onion media path: streams bytes server-side so Tor clients fetch
				// media over the no-exit onion route instead of via a presigned
				// CDN/S3 host through a Tor exit node. Auth-gated like /media/get.
				r.With(httputil.ExtendDeadlines(bulkTransferDeadline)).Get("/media/stream", mediaH.GetStream)
				// Web upload path: the browser can't PUT to a presigned S3 URL, so
				// it posts the ciphertext here (uploader-only, exact declared size).
				r.With(httputil.ExtendDeadlines(bulkTransferDeadline)).Post("/media/upload", mediaH.PostUpload)

				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/devices/push-token", pushH.PostPushToken)
				r.With(httputil.MaxBytes(maxBodyDefault)).Delete("/devices/push-token", pushH.DeletePushToken)

				r.With(httputil.MaxBytes(maxBodyKeyPackages)).Post("/accounts/me/key-packages", kpH.PostMyKeyPackages)
				r.Get("/accounts/me/key-packages/count", kpH.GetMyKeyPackageCount)
				r.Get("/accounts/me/devices/{deviceID}/key-packages", kpH.GetOwnDeviceKeyPackages)
				r.Get("/accounts/{username}/key-package", kpH.GetKeyPackageByUsername)
				r.Get("/accounts/{username}/key-packages", kpH.GetDeviceKeyPackagesByUsername)

				// GIF proxy (Giphy key held server-side; media proxied to hide user IP).
				r.Get("/gifs/search", gifH.GetSearch)
				r.Get("/gifs/trending", gifH.GetTrending)
				r.With(httputil.ExtendDeadlines(bulkTransferDeadline)).Get("/gifs/media", gifH.GetMedia)

				// Short-lived TURN credentials for 1:1 calls.
				r.Get("/turn/credentials", turnH.GetCredentials)

				// User-abuse reports → moderation queue (Apple 1.2 / Play UGC).
				r.With(httputil.MaxBytes(maxBodyDefault)).Post("/reports", modH.PostReport)
			})
		})
	})

	return r
}

// buildS3Client returns a real AWS S3 client if NANB_AWS_REGION + NANB_S3_BUCKET
// are set, otherwise a NilClient that errors on every operation.
func buildS3Client(ctx context.Context) media.S3Client {
	region := os.Getenv("NANB_AWS_REGION")
	bucket := os.Getenv("NANB_S3_BUCKET")
	if region == "" || bucket == "" {
		log.Println("WARN: NANB_AWS_REGION or NANB_S3_BUCKET unset; media uploads will fail until configured")
		return media.NilClient{}
	}
	cli, err := media.NewAWSClient(ctx, media.AWSConfig{Region: region, Bucket: bucket})
	if err != nil {
		log.Printf("WARN: AWS S3 client init failed: %v; falling back to NilClient", err)
		return media.NilClient{}
	}
	return cli
}

// buildCDNSigner wires CloudFront signed-URL downloads when the edge cache is
// configured. All three of NANB_CDN_DOMAIN, NANB_CDN_KEY_ID, and the private
// key (NANB_CDN_PRIVATE_KEY_FILE path, or inline NANB_CDN_PRIVATE_KEY) must be
// set; otherwise the CDN stays off and media downloads use S3 presigned GETs.
// A misconfiguration logs a WARN and returns nil (S3 fallback) rather than
// failing boot — media must keep working.
func buildCDNSigner() media.CDNSigner {
	domain := os.Getenv("NANB_CDN_DOMAIN")
	keyID := os.Getenv("NANB_CDN_KEY_ID")
	if domain == "" || keyID == "" {
		log.Println("media CDN: NANB_CDN_DOMAIN/NANB_CDN_KEY_ID unset; serving media via S3 presigned URLs")
		return nil
	}

	pem := os.Getenv("NANB_CDN_PRIVATE_KEY")
	if pem == "" {
		if path := os.Getenv("NANB_CDN_PRIVATE_KEY_FILE"); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				log.Printf("WARN: media CDN disabled: read %s: %v", path, err)
				return nil
			}
			pem = string(b)
		}
	}
	if pem == "" {
		log.Println("WARN: media CDN disabled: NANB_CDN_PRIVATE_KEY(_FILE) unset")
		return nil
	}

	signer, err := media.NewCloudFrontSigner(media.CloudFrontConfig{
		Domain:        domain,
		KeyID:         keyID,
		PrivateKeyPEM: pem,
	})
	if err != nil {
		log.Printf("WARN: media CDN disabled: %v", err)
		return nil
	}
	log.Printf("media CDN: CloudFront signed URLs enabled (domain=%s key=%s)", domain, keyID)
	return signer
}

// buildVoipPushClient wires the PushKit (VoIP) sender, or returns nil when APNs
// isn't configured. It needs the APNs auth key DIRECTLY — a VoIP push can't go
// through FCM (different topic, different push type), which is why an
// FCM-only deployment has no CallKit ring and iOS falls back to the banner.
//
// Nil-safety note: this returns a typed nil if built carelessly, which would
// defeat the `VoipClient == nil` guard in the service — so bail out with an
// untyped nil before constructing anything.
func buildVoipPushClient() push.VoipPushClient {
	keyPath := os.Getenv("NANB_APNS_KEY_PATH")
	bundleID := os.Getenv("NANB_APNS_BUNDLE_ID")
	if keyPath == "" || bundleID == "" {
		log.Println("push: VoIP (CallKit) ring disabled — set NANB_APNS_KEY_PATH + NANB_APNS_BUNDLE_ID to enable")
		return nil
	}
	key, err := push.LoadAPNSAuthKeyFromFile(keyPath)
	if err != nil {
		log.Printf("WARN: VoIP (CallKit) ring disabled: %v", err)
		return nil
	}
	cfg := push.APNSConfig{
		KeyID:      os.Getenv("NANB_APNS_KEY_ID"),
		TeamID:     os.Getenv("NANB_APNS_TEAM_ID"),
		BundleID:   bundleID,
		AuthKey:    key,
		Production: os.Getenv("NANB_APNS_PRODUCTION") == "true",
	}
	// Build BOTH APNs environments. A PushKit token belongs to the environment
	// the app was SIGNED for, and this fleet runs both at once: TestFlight builds
	// register production tokens, the same commit sideloaded (re-signed with a
	// development profile) registers sandbox ones. NANB_APNS_PRODUCTION only
	// picks which is TRIED FIRST; the client retries the other on the one
	// rejection that means "wrong environment". Same auth key for both.
	other := cfg
	other.Production = !cfg.Production
	log.Printf("push: VoIP (CallKit) ring enabled on %s.voip (production-first=%v, other environment as fallback)",
		bundleID, cfg.Production)
	return push.NewAPNSVoipClient(
		push.NewAPNSTokenClient(cfg),
		push.NewAPNSTokenClient(other),
		bundleID,
	)
}

// buildPushClient assembles a CompositeClient. Each platform is wired only when
// its env vars are set; missing platforms remain nil and CompositeClient
// returns ErrPushNotConfigured for messages targeting them.
func buildPushClient(ctx context.Context) *push.CompositeClient {
	c := &push.CompositeClient{}
	wired := []string{}

	if keyPath := os.Getenv("NANB_APNS_KEY_PATH"); keyPath != "" {
		key, err := push.LoadAPNSAuthKeyFromFile(keyPath)
		if err != nil {
			log.Printf("WARN: APNs disabled: %v", err)
		} else {
			c.APNS = push.NewAPNSClient(push.APNSConfig{
				KeyID:      os.Getenv("NANB_APNS_KEY_ID"),
				TeamID:     os.Getenv("NANB_APNS_TEAM_ID"),
				BundleID:   os.Getenv("NANB_APNS_BUNDLE_ID"),
				AuthKey:    key,
				Production: os.Getenv("NANB_APNS_PRODUCTION") == "true",
			})
			wired = append(wired, "apns")
		}
	}

	if saPath := os.Getenv("NANB_FCM_SERVICE_ACCOUNT_PATH"); saPath != "" {
		sa, err := push.LoadFCMServiceAccountFromFile(saPath)
		if err != nil {
			log.Printf("WARN: FCM disabled: %v", err)
		} else {
			fcm, err := push.NewFCMClient(ctx, push.FCMConfig{ServiceAccountJSON: sa})
			if err != nil {
				log.Printf("WARN: FCM disabled: %v", err)
			} else {
				c.FCM = fcm
				wired = append(wired, "fcm")
			}
		}
	}

	if len(wired) == 0 {
		log.Println("WARN: no push platforms configured; offline message delivery will not wake clients")
	} else {
		log.Printf("push: wired %v", wired)
	}
	return c
}

// buildReportNotifier wires email notifications for new user reports when the
// SMTP vars are set; otherwise reports are stored only (NoopNotifier). Point
// NANB_SMTP_HOST/PORT at SES's SMTP endpoint (or any provider) and set
// NANB_REPORT_EMAIL_TO to start receiving them — no code change required.
func buildReportNotifier() moderation.Notifier {
	host := os.Getenv("NANB_SMTP_HOST")
	to := os.Getenv("NANB_REPORT_EMAIL_TO")
	from := envOrDefault("NANB_REPORT_EMAIL_FROM", os.Getenv("NANB_SMTP_USERNAME"))
	if host == "" || to == "" || from == "" {
		log.Println("WARN: NANB_SMTP_HOST/NANB_REPORT_EMAIL_TO unset; user reports stored only (no email)")
		return moderation.NoopNotifier{}
	}
	log.Printf("moderation: report email notifications enabled (to=%s)", to)
	return moderation.NewSMTPNotifier(moderation.SMTPConfig{
		Host:     host,
		Port:     envOrDefault("NANB_SMTP_PORT", "587"),
		Username: os.Getenv("NANB_SMTP_USERNAME"),
		Password: os.Getenv("NANB_SMTP_PASSWORD"),
		From:     from,
		To:       to,
	})
}

func envOrDefault(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// runtimeConfig holds the operator-tunable knobs. Each field is bounded by
// a hardcoded MAXIMUM that matches the ship-day default — operators can
// only LOWER limits (e.g. shorter retention, smaller cap) for stricter
// privacy or to fit a smaller deployment. They cannot raise them past the
// security/UX-sensitive defaults the protocol was specced against.
type runtimeConfig struct {
	ConversationCap     int
	EnvelopeRetention   time.Duration
	MediaRetention      time.Duration
	MediaMaxSizeBytes   int64
	MessageMaxSizeBytes int
	PresignTTL          time.Duration
	JWTLifetime         time.Duration
	ChallengeLifetime   time.Duration
	KeyPackageLifetime  time.Duration
	WebDeviceLifetime   time.Duration
	RetentionInterval   time.Duration
	RetentionBatch      int
	GroupMaxMembers     int
	TurnTTL             time.Duration
}

func loadConfig() runtimeConfig {
	cfg := runtimeConfig{
		ConversationCap:     clampInt("NANB_CONVERSATION_CAP", 5000, 5000),
		EnvelopeRetention:   clampDays("NANB_ENVELOPE_RETENTION_DAYS", 30, 30),
		MediaRetention:      clampDays("NANB_MEDIA_RETENTION_DAYS", 30, 30),
		MediaMaxSizeBytes:   int64(clampInt("NANB_MEDIA_MAX_SIZE_MB", 100, 100)) << 20,
		MessageMaxSizeBytes: clampInt("NANB_MESSAGE_MAX_SIZE_KB", 2048, 2048) << 10,
		PresignTTL:          clampMinutes("NANB_PRESIGN_TTL_MINUTES", 15, 15),
		JWTLifetime:         clampHours("NANB_JWT_LIFETIME_HOURS", 24, 24),
		ChallengeLifetime:   clampSeconds("NANB_CHALLENGE_LIFETIME_SECONDS", 120, 120),
		KeyPackageLifetime:  clampDays("NANB_KEY_PACKAGE_LIFETIME_DAYS", 30, 30),
		// Web (browser) devices expire this many days after linking; operators
		// may shorten or lengthen it (cap 365d).
		WebDeviceLifetime:   clampDays("NANB_WEB_DEVICE_LIFETIME_DAYS", 30, 365),
		// Every 10 min, up to retention.MaxBatchesPerRun batches of 500 per
		// record type per tick: ~60k/hr each. The old 100-per-hour pace could
		// not keep up, so data outlived the 30-day retention promise.
		RetentionInterval:   clampMinutes("NANB_RETENTION_INTERVAL_MINUTES", 10, 60),
		RetentionBatch:      clampInt("NANB_RETENTION_BATCH", 500, 1000),
		GroupMaxMembers:     clampInt("NANB_GROUP_MAX_MEMBERS", 32, 32),
		// TURN credential lifetime. 12h default keeps a call alive across the
		// short re-fetch the client does; cap 24h.
		TurnTTL: clampSeconds("NANB_TURN_TTL_SECONDS", 43200, 86400),
	}
	log.Printf("config: conversation_cap=%d envelope_retention=%s media_retention=%s media_max_size=%dMB message_max_size=%dKB group_max_members=%d",
		cfg.ConversationCap, cfg.EnvelopeRetention, cfg.MediaRetention,
		cfg.MediaMaxSizeBytes>>20, cfg.MessageMaxSizeBytes>>10, cfg.GroupMaxMembers)
	return cfg
}

// clampInt reads `key` as a positive integer; if unset/invalid returns def;
// otherwise returns the parsed value clamped to [1, max]. Logs a warning if
// the operator's value is clamped or rejected.
func clampInt(key string, def, max int) int {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		log.Printf("WARN: %s=%q invalid; using default %d", key, raw, def)
		return def
	}
	if v > max {
		log.Printf("WARN: %s=%d exceeds max %d; clamping", key, v, max)
		return max
	}
	return v
}

func clampDays(key string, def, max int) time.Duration {
	return time.Duration(clampInt(key, def, max)) * 24 * time.Hour
}

func clampHours(key string, def, max int) time.Duration {
	return time.Duration(clampInt(key, def, max)) * time.Hour
}

func clampMinutes(key string, def, max int) time.Duration {
	return time.Duration(clampInt(key, def, max)) * time.Minute
}

func clampSeconds(key string, def, max int) time.Duration {
	return time.Duration(clampInt(key, def, max)) * time.Second
}

// splitCSV splits a comma-separated env value into trimmed, non-empty items.
func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// loadOrGenerateJWTKey decodes the configured Ed25519 signing key. When the key
// is unset it fails closed UNLESS devMode is set — the ephemeral-key convenience
// is for local development only, since a stable key is what keeps sessions valid
// across restarts.
func loadOrGenerateJWTKey(b64 string, devMode bool) (ed25519.PrivateKey, error) {
	if b64 == "" {
		if !devMode {
			return nil, errMissingJWTKeyProd
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		log.Println("WARN: NANB_DEV_MODE=true and NANB_JWT_PRIV_KEY_B64 unset; generated ephemeral key (DEV ONLY — not stable across restarts)")
		return priv, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errInvalidJWTKey
	}
	return ed25519.PrivateKey(raw), nil
}
