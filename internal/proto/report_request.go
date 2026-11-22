package proto

// ReportedMessage is a single piece of evidence attached to a user report: a
// recent message FROM the reported user, decrypted on the reporter's device and
// forwarded for moderation review. The server otherwise never sees plaintext —
// these are included only because the reporter chose to report them.
type ReportedMessage struct {
	Sender string `json:"sender"`            // display label of the reported user
	Body   string `json:"body"`              // text / caption ("" for media without a caption)
	Kind   string `json:"kind"`              // text|image|video|voice|file|gif
	SentAt string `json:"sent_at,omitempty"` // RFC3339 UTC, best-effort
}

// ReportRequest is the body of POST /reports. The reporter is taken from the
// authenticated JWT and is never trusted from the body; the body carries who is
// being reported, why, and optional forwarded evidence.
type ReportRequest struct {
	ReportedAccountID string            `json:"reported_account_id"`
	ReportedUsername  string            `json:"reported_username"`
	ConversationID    string            `json:"conversation_id,omitempty"`
	Reason            string            `json:"reason"`
	Note              string            `json:"note,omitempty"`
	Messages          []ReportedMessage `json:"messages,omitempty"`
}

// ReportResponse is returned on a successful POST /reports.
type ReportResponse struct {
	OK       bool   `json:"ok"`
	ReportID string `json:"report_id"`
}
