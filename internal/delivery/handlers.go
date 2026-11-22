package delivery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/httputil"
	"github.com/nanb/nanb-server/internal/proto"
)

// ServiceAPI is the subset of Service the handlers depend on.
type ServiceAPI interface {
	SubmitMessage(ctx context.Context, senderDeviceID string, req proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error)
	CatchupMessages(ctx context.Context, deviceID string, req proto.CatchupRequest) (proto.CatchupResponse, error)
	AckMessages(ctx context.Context, deviceID string, req proto.AckRequest) (proto.AckResponse, error)
	ConfirmReceived(ctx context.Context, deviceID, envelopeID string) (proto.ConfirmReceivedResponse, error)
	GetEnvelopeByIDForRecipient(ctx context.Context, envelopeID, recipientDeviceID string) (proto.Envelope, error)
}

// AccessKeyVerifier authorizes an UNAUTHENTICATED sealed send (sealed-sender
// Phase 2 — unidentified access). Given the recipient device and the UAK the
// sender presents, it reports whether the key matches the recipient account's
// stored commitment, returning the server-authoritative recipient ACCOUNT id.
// ok=false with a nil error means "not authorized" (recipient hasn't enabled
// unidentified access, or the key is wrong) — NOT a server error. Wired from the
// identity service; optional (nil disables the sealed-unauth endpoint).
type AccessKeyVerifier interface {
	VerifyAccessKey(ctx context.Context, recipientDeviceID string, presentedKey []byte) (accountID string, ok bool, err error)
}

// HubAccessor is the subset of Hub used by the WebSocket handler.
type HubAccessor interface {
	Register(deviceID string, conn Conn)
	Unregister(deviceID string, conn Conn)
	// Broadcast delivers an envelope to a device's live connection (if any).
	// Used to relay ephemeral typing signals. Returns false when not connected.
	Broadcast(deviceID string, env proto.Envelope) bool
}

type Handlers struct {
	svc ServiceAPI
	hub HubAccessor

	// deviceActive, when set, is called at the WS handshake to reject a device
	// whose session was revoked (e.g. a recovery-phrase takeover on another
	// phone). nil → check skipped (JWT signature + expiry remain the only gate,
	// as before). One DB read per connection, not per request.
	deviceActive func(context.Context, string) bool

	// Per-account inbound WS-send limiters, created lazily — bounds how fast an
	// account's device sockets can COLLECTIVELY reach the DB-insert path, on top
	// of the per-connection limiter. (v1: not garbage-collected; bounded by the
	// active-account count.)
	acctLimMu sync.Mutex
	acctLim   map[string]*rate.Limiter

	// verifier authorizes unauthenticated sealed sends (Phase 2). nil → the
	// /messages/sealed endpoint is disabled (503).
	verifier AccessKeyVerifier
	// uakFailures throttles repeated FAILED access-key attempts on the sealed
	// endpoint. Valid sealed sends are never rate limited: there used to be a
	// global bucket spent BEFORE the key check (one flooder starved everyone's
	// sealed delivery, pushing them onto the less private authed path) and a
	// per-recipient one (a send limit); both are gone.
	uakFailures *AccessKeyFailureLimiter

	// typingResolver resolves the sender's liveness and the recipient device's
	// owning account for typing frames (the 1:1 membership check). Wired in
	// main with the short-TTL cached resolver, so a typing burst doesn't cost a
	// DB read per frame. nil → typing frames are dropped (fail closed).
	typingResolver RecipientResolver

	// tickets, when set, lets a browser authenticate /ws with a one-time ticket
	// (browsers cannot send an Authorization header on a WebSocket). nil → the
	// ticket path is off and /ws accepts only the Authorization header, as before.
	tickets *WSTicketStore
	// webOriginHosts are the browser Origin hosts allowed to open /ws. Empty →
	// coder/websocket's default same-origin check (native clients send no Origin).
	webOriginHosts []string
}

func NewHandlers(svc ServiceAPI, hub HubAccessor) *Handlers {
	return &Handlers{
		svc:         svc,
		hub:         hub,
		acctLim:     map[string]*rate.Limiter{},
		uakFailures: NewAccessKeyFailureLimiter(nil),
	}
}

// SetTypingResolver installs the resolver typing frames are checked against
// (see Handlers.typingResolver). Wired in main.
func (h *Handlers) SetTypingResolver(r RecipientResolver) { h.typingResolver = r }

// SetAccessKeyVerifier installs the UAK verifier that gates the unauthenticated
// sealed-send endpoint (wired in main from the identity service). Optional; when
// unset, POST /messages/sealed returns 503.
func (h *Handlers) SetAccessKeyVerifier(v AccessKeyVerifier) { h.verifier = v }

// SetDeviceValidator installs the per-connection active-device check used by
// HandleWS (wired in main from the identity store). Optional; when unset the
// handshake skips the check.
func (h *Handlers) SetDeviceValidator(fn func(context.Context, string) bool) {
	h.deviceActive = fn
}

func (h *Handlers) PostMessage(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}

	var req proto.SubmitMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}

	resp, err := h.svc.SubmitMessage(r.Context(), claims.DeviceID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// maxDeviceIDLen bounds a client-supplied device id before it is used as a
// lookup or limiter key (real ids are 36-char UUIDs).
const maxDeviceIDLen = 64

// PostSealedMessage handles POST /messages/sealed — the UNAUTHENTICATED sealed
// send (sealed-sender Phase 2, unidentified access). There is NO JWT: the sender
// presents the RECIPIENT's unidentified-access key (UAK), proving it's an
// authorized contact without revealing WHICH contact. The server verifies the
// UAK against the recipient's stored commitment, rate-limits per recipient, and
// stores the envelope with NO sender (the zero-UUID sentinel). So even an
// actively-logging server learns only "device D received an opaque blob at T",
// never who sent it. Falls back at the client to the authenticated path on 403
// (recipient hasn't enabled it / wrong key) or 429 (too many FAILED attempts
// from this source — a valid send is never rate limited).
func (h *Handlers) PostSealedMessage(w http.ResponseWriter, r *http.Request) {
	if h.verifier == nil {
		writeJSON(w, http.StatusServiceUnavailable, proto.APIError{Code: proto.ErrCodeInternal, Message: "sealed delivery unavailable"})
		return
	}
	var req proto.SubmitMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}
	// This path only carries a sealed, singular send authorized by a UAK.
	if req.EnvelopeType != proto.EnvelopeTypeSealed || req.RecipientDeviceID == "" || len(req.AccessKey) == 0 ||
		len(req.RecipientDeviceID) > maxDeviceIDLen {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "sealed send requires recipient_device_id + access_key"})
		return
	}

	// Only a source that keeps presenting WRONG keys is held back, and only
	// until its failure budget refills. Its key never names the sender: it is
	// the client IP (or the shared onion key), kept in memory only while
	// failures are being counted, and never for a send that succeeds.
	clientKey := httputil.ClientKey(r)
	if h.uakFailures.Blocked(clientKey, req.RecipientDeviceID) {
		writeJSON(w, http.StatusTooManyRequests, proto.APIError{Code: proto.ErrCodeForbidden, Message: "rate limited"})
		return
	}

	accountID, ok, err := h.verifier.VerifyAccessKey(r.Context(), req.RecipientDeviceID, req.AccessKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIError{Code: proto.ErrCodeInternal, Message: "internal"})
		return
	}
	if !ok {
		h.uakFailures.RecordFailure(clientKey, req.RecipientDeviceID)
		// Single response for "unknown recipient" and "wrong key" — don't leak
		// which, and don't reveal whether a device exists.
		writeJSON(w, http.StatusForbidden, proto.APIError{Code: proto.ErrCodeForbidden, Message: "access denied"})
		return
	}

	// Server-authoritative recipient account (never trust the client's value),
	// and an explicit sentinel sender so nothing client-supplied is ever stored.
	req.RecipientAccountID = accountID
	req.AccessKey = nil
	resp, err := h.svc.SubmitMessage(r.Context(), proto.SealedSentinelUUID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// PostReceived handles a recipient device's transport-level "delivered"
// confirmation: its background push handler reports that a wakeup for the
// envelope landed, WITHOUT decrypting it. The service relays a delivery-status
// signal to the original sender (best-effort).
func (h *Handlers) PostReceived(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}

	var req proto.ConfirmReceivedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}

	resp, err := h.svc.ConfirmReceived(r.Context(), claims.DeviceID, req.EnvelopeID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) PostCatchup(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}

	var req proto.CatchupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}

	resp, err := h.svc.CatchupMessages(r.Context(), claims.DeviceID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) PostAck(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}

	var req proto.AckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}

	resp, err := h.svc.AckMessages(r.Context(), claims.DeviceID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// WSConn adapts a coder/websocket connection to the delivery.Conn interface.
// The mutex serializes WriteEnvelope: coder/websocket only allows one
// in-flight write per connection, and SubmitMessage can call Broadcast
// concurrently from multiple HTTP handler goroutines.
type WSConn struct {
	mu sync.Mutex
	c  *websocket.Conn
}

// Close ends the connection with a policy-violation status (the device was
// revoked). The read loop then returns and the handler cleans up.
func (w *WSConn) Close() error {
	return w.c.Close(websocket.StatusPolicyViolation, "device revoked")
}

func (w *WSConn) WriteEnvelope(env proto.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return wsjson.Write(ctx, w.c, env)
}

// WriteJSON writes v as one text frame, serialized against WriteEnvelope via the
// same mutex (coder/websocket allows one in-flight write per connection). Used
// for send_ack / send_error replies, which race Broadcast writes from other
// goroutines.
func (w *WSConn) WriteJSON(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return wsjson.Write(ctx, w.c, v)
}

// HandleWS upgrades to WebSocket and registers with the hub.
// JWT is read from the Authorization header ONLY — a ?token= query param
// was supported once, but request URLs land verbatim in the request log
// (and any proxy logs), leaking live bearer tokens. The Dart client sends
// the header (dart:io WebSocket supports custom headers; browsers don't,
// but there is no browser client).
func (h *Handlers) HandleWS(jwtPubKey ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := h.authenticateWS(r, jwtPubKey)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Reject a revoked device (e.g. a recovery-phrase takeover on another
		// phone) at the handshake, so the old phone is kicked on its next
		// reconnect instead of lingering until its JWT expires. The client's
		// reconnect supervisor turns this rejection into a token refresh, which
		// then fails the active-device check → sign-out + local wipe.
		if h.deviceActive != nil && !h.deviceActive(r.Context(), claims.DeviceID) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.webOriginHosts})
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusInternalError, "closing")
		// Bound inbound frame size: a send frame carries an MLS/ratchet
		// ciphertext (small — media bytes go to S3 separately), so this is
		// generous headroom while capping memory + flood. (coder/websocket's
		// default read limit is 32KiB, which a real ciphertext can exceed.)
		c.SetReadLimit(maxWSFrameBytes)

		conn := &WSConn{c: c}
		h.hub.Register(claims.DeviceID, conn)
		defer h.hub.Unregister(claims.DeviceID, conn)
		log.Printf("ws: device %s connected", claims.DeviceID)

		// Heartbeat: without it a half-open TCP connection (NAT idle drop,
		// network switch) looks alive forever — WriteEnvelope lands in the
		// kernel buffer and "succeeds", so Broadcast never reports failure
		// and the recipient silently misses real-time delivery until their
		// next catchup. Ping waits for the pong; a miss closes the conn,
		// which unblocks the read loop below and unregisters the dead conn.
		ctx := r.Context()
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// 30s pong deadline (was 10s): a dozing phone's WiFi
					// power-save can delay frames for tens of seconds; the
					// tight deadline made screen-off devices churn through
					// reconnect cycles every ~15-30s. Detection of a truly
					// dead conn now takes up to ~60s, which catchup covers.
					pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
					err := c.Ping(pingCtx)
					cancel()
					if err != nil {
						log.Printf("ws: device %s heartbeat failed: %v", claims.DeviceID, err)
						_ = c.Close(websocket.StatusPolicyViolation, "heartbeat timeout")
						return
					}
				}
			}
		}()

		// Per-connection inbound send limiter (token bucket): a cheap frame on an
		// open socket is far easier to flood than a discrete POST, so cap what
		// reaches the DB-insert path. Checked before any work.
		connLimiter := rate.NewLimiter(rate.Limit(wsSendRatePerSec), wsSendBurst)
		// Acks get their own bucket: a catch-up of N messages produces up to N
		// ack frames in a burst (older clients send one per envelope). Sharing
		// the send bucket dropped most of them silently, so the same envelopes
		// were drained again on every launch, and it starved the user's first
		// sends of tokens. An ack only marks the caller's own rows consumed.
		ackLimiter := rate.NewLimiter(rate.Limit(wsAckRatePerSec), wsAckBurst)
		// Typing is an ephemeral hint, not a message, so excess frames are
		// simply dropped: a flood can't turn into relay + lookup work.
		typingLimiter := rate.NewLimiter(rate.Limit(wsTypingRatePerSec), wsTypingBurst)

		// Read loop: inbound frames are either EPHEMERAL signals (typing —
		// relayed, never persisted) or "send" frames (a message POSTed over the
		// live socket — the same path as POST /messages). Also keeps the
		// connection alive + processes pings + close frames.
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				log.Printf("ws: device %s read loop ended: %v", claims.DeviceID, err)
				return
			}
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &probe) != nil {
				continue
			}
			switch probe.Type {
			case proto.EnvelopeTypeTyping:
				// A typing frame is ~150 bytes; a bigger one is not a typing frame.
				if len(data) > maxTypingFrameBytes || !typingLimiter.Allow() {
					continue
				}
				h.relayTyping(ctx, claims, data)
			case wsFrameTypeSend:
				// Rate-limit BEFORE touching the DB or spawning a worker, so a
				// frame flood is rejected near-free (per-connection AND per-account).
				if !connLimiter.Allow() || !h.accountLimiter(claims.AccountID).Allow() {
					var m wsSendMeta
					_ = json.Unmarshal(data, &m)
					_ = conn.WriteJSON(wsSendErrorFrame{
						Type: wsFrameTypeSendError, ClientRef: m.ClientRef,
						Code: proto.ErrCodeForbidden, Message: "rate limited",
					})
					continue
				}
				// Own goroutine so a slow DB insert can't head-of-line-block this
				// socket's reads / heartbeat pongs.
				go h.handleWSSend(ctx, claims, conn, data)
			case wsFrameTypeAck:
				// Same per-connection / per-account flood guard as sends (acks
				// also hit the DB). Dropping under flood is safe — the ack is
				// best-effort and redelivery covers a missed one.
				if !ackLimiter.Allow() {
					continue
				}
				go h.handleWSAck(ctx, claims, data)
			case wsFrameTypeCatchup:
				// Reads only, but it is a DB query and a potentially large
				// response, so it takes the same flood guard as sends/acks. On
				// rejection the client falls back to HTTP rather than silently
				// draining nothing.
				if !connLimiter.Allow() || !h.accountLimiter(claims.AccountID).Allow() {
					var m wsSendMeta
					_ = json.Unmarshal(data, &m)
					_ = conn.WriteJSON(wsCatchupErrorFrame{
						Type: wsFrameTypeCatchupError, ClientRef: m.ClientRef,
						Code: proto.ErrCodeForbidden, Message: "rate limited",
					})
					continue
				}
				// Own goroutine: a drain query must not head-of-line-block this
				// socket's reads or its heartbeat pongs.
				go h.handleWSCatchup(ctx, claims, conn, data)
			case wsFrameTypePing:
				// App-level liveness probe — echo a pong. Cheap (no DB/relay),
				// so not rate-limited; lets the client confirm the socket is
				// responsive on resume and skip a needless (Tor-costly) reconnect.
				_ = conn.WriteJSON(wsPongFrame{Type: wsFrameTypePong})
			default:
				// Unknown frame type — ignore (forward-compat).
			}
		}
	}
}

// WS-send: clients may POST a message over the live socket (a "send" frame)
// instead of a fresh HTTPS request — same encrypted payload, same auth, same
// server work, just no per-message connection/TLS setup. The server replies on
// the same socket with a send_ack / send_error correlated by client_ref.
const (
	wsFrameTypeSend      = "send"
	wsFrameTypeSendAck   = "send_ack"
	wsFrameTypeSendError = "send_error"
	// Receive-path: the client marks envelopes consumed over the socket instead
	// of POST /messages/ack. Fire-and-forget — no reply frame; an ack is
	// idempotent, and a lost one just redelivers on the next catchup.
	wsFrameTypeAck = "ack"

	// App-level liveness probe: the client sends a "ping" on app-resume to
	// confirm the socket is actually responsive before deciding to reconnect
	// (a reconnect is costly over Tor). The server echoes a "pong". Distinct
	// from the websocket protocol-level ping the library auto-handles.
	wsFrameTypePing = "ping"
	wsFrameTypePong = "pong"

	// Receive-path drain over the live socket, mirroring wsFrameTypeSend on the
	// send path. POST /messages/catchup costs a fresh HTTPS connection, and it
	// runs at the worst possible moment: right after connect, concurrently with
	// the rest of the connect fan-out, so it cannot reuse a pooled connection
	// and pays a full DNS+TCP+TLS setup. Measured on-device 2026-08-22 that one
	// request took 644-957ms while the server answered it in under 10ms — more
	// than half the entire catchup. Over the socket it costs neither.
	wsFrameTypeCatchup       = "catchup"
	wsFrameTypeCatchupResult = "catchup_result"
	wsFrameTypeCatchupError  = "catchup_error"

	// Max inbound WS frame. A ciphertext is small (media bytes go to S3
	// separately), so this is generous headroom while bounding memory + flood.
	maxWSFrameBytes = 512 * 1024

	// Per-connection / per-account inbound send rate (token buckets).
	wsSendRatePerSec = 8
	wsSendBurst      = 16
	wsAcctRatePerSec = 16
	wsAcctBurst      = 32

	// Per-connection inbound ack rate, separate from sends (see ackLimiter).
	wsAckRatePerSec = 50
	wsAckBurst      = 300

	// Per-connection typing-frame rate. The client sends one frame per peer
	// device on each start/stop, so a few per second covers a multi-device peer.
	wsTypingRatePerSec = 5
	wsTypingBurst      = 15
)

// wsSendMeta pulls just the correlation id from a send frame; the rest of the
// frame is decoded as a proto.SubmitMessageRequest, exactly like the HTTP body.
type wsSendMeta struct {
	ClientRef string `json:"client_ref"`
}

type wsSendAck struct {
	Type       string    `json:"type"`
	ClientRef  string    `json:"client_ref"`
	EnvelopeID string    `json:"envelope_id"`
	ServerTS   time.Time `json:"server_ts"`
}

type wsSendErrorFrame struct {
	Type      string          `json:"type"`
	ClientRef string          `json:"client_ref"`
	Code      proto.ErrorCode `json:"code"`
	Message   string          `json:"message"`
}

// wsAckFrame is the receive-path ack: the device reports which envelopes it has
// consumed so they stop redelivering.
type wsAckFrame struct {
	Type        string   `json:"type"`
	EnvelopeIDs []string `json:"envelope_ids"`
}

// wsPongFrame answers a client "ping" liveness probe.
type wsPongFrame struct {
	Type string `json:"type"`
}

// handleWSSend processes one "send" frame: it does EXACTLY what POST /messages
// does — decode a SubmitMessageRequest and submit it with the AUTHENTICATED
// sender (claims.DeviceID, never a frame field) — then replies on the socket
// with send_ack / send_error correlated by client_ref. The underlying
// SubmitMessage keeps the store→Broadcast→FCM-fallback offline path intact.
// Runs in its own goroutine (the caller already rate-limited).
func (h *Handlers) handleWSSend(ctx context.Context, claims crypto.JWTClaims, conn *WSConn, data []byte) {
	var meta wsSendMeta
	_ = json.Unmarshal(data, &meta)

	// JWT expiry on the long-lived socket: a token that expired since the
	// upgrade must not keep sending just because the connection stayed open.
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		_ = conn.WriteJSON(wsSendErrorFrame{
			Type: wsFrameTypeSendError, ClientRef: meta.ClientRef,
			Code: proto.ErrCodeUnauthorized, Message: "token expired",
		})
		return
	}

	var req proto.SubmitMessageRequest
	if err := json.Unmarshal(data, &req); err != nil {
		_ = conn.WriteJSON(wsSendErrorFrame{
			Type: wsFrameTypeSendError, ClientRef: meta.ClientRef,
			Code: proto.ErrCodeBadRequest, Message: "invalid send frame",
		})
		return
	}

	resp, err := h.svc.SubmitMessage(ctx, claims.DeviceID, req)
	if err != nil {
		code, msg := wsErrParts(err)
		_ = conn.WriteJSON(wsSendErrorFrame{
			Type: wsFrameTypeSendError, ClientRef: meta.ClientRef,
			Code: code, Message: msg,
		})
		return
	}
	_ = conn.WriteJSON(wsSendAck{
		Type: wsFrameTypeSendAck, ClientRef: meta.ClientRef,
		EnvelopeID: resp.EnvelopeID, ServerTS: resp.ServerTS,
	})
}

// handleWSAck consumes envelopes the client reports as processed (marks them
// acked so they stop redelivering) — the same as POST /messages/ack, but
// fire-and-forget over the socket. No reply: an ack is idempotent, and a lost
// one redelivers on the next catchup. Runs in its own goroutine.
func (h *Handlers) handleWSAck(ctx context.Context, claims crypto.JWTClaims, data []byte) {
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		return // an expired token can't ack
	}
	var f wsAckFrame
	if err := json.Unmarshal(data, &f); err != nil || len(f.EnvelopeIDs) == 0 {
		return
	}
	if _, err := h.svc.AckMessages(ctx, claims.DeviceID, proto.AckRequest{EnvelopeIDs: f.EnvelopeIDs}); err != nil {
		log.Printf("ws: device %s ack failed: %v", claims.DeviceID, err)
	}
}

// handleWSCatchup serves a receive-path drain over the live socket — the same
// service call as POST /messages/catchup, just without a fresh connection.
//
// Replies with a catchup_result (or catchup_error) correlated by client_ref, so
// the client can await it exactly like a send_ack. Any failure is reported
// rather than swallowed: the client must be able to tell "nothing to drain"
// apart from "that didn't work, use HTTP", or a broken socket path would look
// like an empty inbox.
func (h *Handlers) handleWSCatchup(ctx context.Context, claims crypto.JWTClaims, conn *WSConn, data []byte) {
	var f wsCatchupFrame
	if err := json.Unmarshal(data, &f); err != nil {
		_ = conn.WriteJSON(wsCatchupErrorFrame{
			Type: wsFrameTypeCatchupError, ClientRef: f.ClientRef,
			Code: proto.ErrCodeBadRequest, Message: "invalid catchup frame",
		})
		return
	}
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		_ = conn.WriteJSON(wsCatchupErrorFrame{
			Type: wsFrameTypeCatchupError, ClientRef: f.ClientRef,
			Code: proto.ErrCodeUnauthorized, Message: "token expired",
		})
		return
	}
	resp, err := h.svc.CatchupMessages(ctx, claims.DeviceID, proto.CatchupRequest{
		SinceServerTS: f.SinceServerTS,
		Limit:         f.Limit,
	})
	if err != nil {
		code, msg := wsErrParts(err)
		_ = conn.WriteJSON(wsCatchupErrorFrame{
			Type: wsFrameTypeCatchupError, ClientRef: f.ClientRef,
			Code: code, Message: msg,
		})
		return
	}
	_ = conn.WriteJSON(wsCatchupResultFrame{
		Type:      wsFrameTypeCatchupResult,
		ClientRef: f.ClientRef,
		Envelopes: resp.Envelopes,
	})
}

// wsCatchupFrame is a drain request over the socket. Mirrors the HTTP
// CatchupRequest body plus the correlation id.
type wsCatchupFrame struct {
	ClientRef     string     `json:"client_ref"`
	SinceServerTS time.Time `json:"since_server_ts,omitempty"`
	Limit         int        `json:"limit,omitempty"`
}

type wsCatchupResultFrame struct {
	Type      string           `json:"type"`
	ClientRef string           `json:"client_ref"`
	Envelopes []proto.Envelope `json:"envelopes"`
}

type wsCatchupErrorFrame struct {
	Type      string          `json:"type"`
	ClientRef string          `json:"client_ref"`
	Code      proto.ErrorCode `json:"code"`
	Message   string          `json:"message"`
}

// wsErrParts mirrors writeAPIError: extract a proto.APIError's code+message, or
// fall back to a generic internal error.
func wsErrParts(err error) (proto.ErrorCode, string) {
	var apiErr proto.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code, apiErr.Message
	}
	return proto.ErrCodeInternal, "internal"
}

// accountLimiter returns the lazily-created per-account inbound-send limiter.
func (h *Handlers) accountLimiter(accountID string) *rate.Limiter {
	h.acctLimMu.Lock()
	defer h.acctLimMu.Unlock()
	lim := h.acctLim[accountID]
	if lim == nil {
		lim = rate.NewLimiter(rate.Limit(wsAcctRatePerSec), wsAcctBurst)
		h.acctLim[accountID] = lim
	}
	return lim
}

func extractToken(r *http.Request) string {
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, prefix) {
		return strings.TrimPrefix(authz, prefix)
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, err error) {
	var apiErr proto.APIError
	if errors.As(err, &apiErr) {
		writeJSON(w, statusForCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusInternalServerError, proto.APIError{Code: proto.ErrCodeInternal, Message: "internal"})
}

func statusForCode(code proto.ErrorCode) int {
	switch code {
	case proto.ErrCodeBadRequest:
		return http.StatusBadRequest
	case proto.ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case proto.ErrCodeForbidden:
		return http.StatusForbidden
	case proto.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case proto.ErrCodeEnvelopeNotFound:
		return http.StatusNotFound
	case proto.ErrCodeAccountNotFound:
		// "recipient account deleted or device revoked" is a DEFINITIVE verdict
		// about the addressee, not a server fault — the client's "peer switched
		// phones" recovery (_isPeerDeviceGone -> _reestablishPeerSession) keys on
		// it to re-resolve the peer's current device + sealing key. Falling
		// through to `default` reported it as 500, which the client's transient
		// retry treats as "server hiccup, try again": the send retried, failed,
		// and was finally marked failed WITHOUT ever re-resolving the peer. So a
		// peer that wiped + restored stayed unreachable until the app restarted.
		return http.StatusNotFound
	case proto.ErrCodeMailboxFull:
		// 507 Insufficient Storage: the server answered (so the client's
		// transient retry doesn't spin), but as a 5xx the client's per-device
		// fan-out leg retry (FanoutLegRetry: status >= 500) re-tries it later,
		// by which time the recipient may have drained its queue. NOT 429 —
		// existing app builds render that as "Sending too fast".
		return http.StatusInsufficientStorage
	default:
		return http.StatusInternalServerError
	}
}

// GetEnvelopeByID — GET /messages/by-id/{envelope_id}
// Used by the iOS Notification Service Extension. Returns 404 if the
// envelope isn't addressed to the caller (server-side enumeration protection).
func (h *Handlers) GetEnvelopeByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "no session"})
		return
	}
	envID := chi.URLParam(r, "envelope_id")
	e, err := h.svc.GetEnvelopeByIDForRecipient(r.Context(), envID, claims.DeviceID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}
