package delivery

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/proto"
)

const (
	// maxTypingFrameBytes: a real typing frame is ~150 bytes. Anything larger
	// is dropped before it is parsed a second time.
	maxTypingFrameBytes = 1024

	// oneToOneConversationPrefix + two 36-char account UUIDs joined by ':' is
	// the only conversation id a typing frame can legitimately carry — typing
	// is 1:1 only, and the client derives the id from both account ids (see
	// oneToOneConversationID). maxTypingConversationIDLen is that length.
	oneToOneConversationPrefix = "1to1:"
	accountIDLen               = 36
	maxTypingConversationIDLen = len(oneToOneConversationPrefix) + accountIDLen + 1 + accountIDLen
)

// wsInboundFrame is the shape a client sends UP the WebSocket for a typing
// signal (send frames decode as proto.SubmitMessageRequest instead).
type wsInboundFrame struct {
	Type              string `json:"type"`
	ConversationID    string `json:"conversation_id"`
	RecipientDeviceID string `json:"recipient_device_id"`
	IsTyping          bool   `json:"is_typing"`
}

// relayTyping forwards a typing signal to the recipient's live WS connection —
// best-effort, never persisted — but only when it is a signal the sender is
// entitled to send:
//
//   - the sender device is still active (revoked/expired after its socket
//     opened → dropped);
//   - the recipient device is live, and the conversation is THE 1:1 between
//     the sender's account and the recipient's account. The server keeps no
//     conversation table, but a 1:1 id is derived from the two account ids, so
//     this is a real membership check: nobody can inject "typing…" into a
//     conversation they are not part of.
//
// SenderDeviceID on the relayed envelope is the AUTHENTICATED caller — never
// taken from the frame. Lookups go through typingResolver (cached in
// production), so a stream of frames doesn't cost a DB read each.
func (h *Handlers) relayTyping(ctx context.Context, claims crypto.JWTClaims, data []byte) {
	if h.typingResolver == nil {
		return
	}
	var f wsInboundFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	if f.Type != proto.EnvelopeTypeTyping || f.RecipientDeviceID == "" ||
		len(f.RecipientDeviceID) > maxDeviceIDLen ||
		len(f.ConversationID) > maxTypingConversationIDLen {
		return
	}
	if live, err := h.typingResolver.RecipientLive(ctx, claims.DeviceID); err != nil || !live {
		return
	}
	recipientAccountID, live, err := h.typingResolver.AccountForDevice(ctx, f.RecipientDeviceID)
	if err != nil || !live {
		return
	}
	if f.ConversationID != oneToOneConversationID(claims.AccountID, recipientAccountID) {
		return
	}
	b := byte(0)
	if f.IsTyping {
		b = 1
	}
	h.hub.Broadcast(f.RecipientDeviceID, proto.Envelope{
		Version:           "v1",
		Domain:            "nanb.link",
		EnvelopeType:      proto.EnvelopeTypeTyping,
		ConversationID:    f.ConversationID,
		SenderDeviceID:    claims.DeviceID,
		RecipientDeviceID: f.RecipientDeviceID,
		Ciphertext:        []byte{b},
		ServerTS:          time.Now(),
	})
}

// oneToOneConversationID mirrors the client's Conversation.oneToOneId: the two
// account ids sorted lexically, so both participants derive the same id.
func oneToOneConversationID(accountA, accountB string) string {
	if accountB < accountA {
		accountA, accountB = accountB, accountA
	}
	return oneToOneConversationPrefix + accountA + ":" + accountB
}
