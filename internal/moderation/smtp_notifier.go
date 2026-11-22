package moderation

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

// SMTPConfig configures email notifications for new reports. Email is enabled
// only when Host, From, and To are all set (see main.buildReportNotifier).
// Point Host/Port at SES's SMTP endpoint (or any provider) to start receiving
// reports — no code change required.
type SMTPConfig struct {
	Host     string // SMTP server host, no port (e.g. email-smtp.us-west-1.amazonaws.com)
	Port     string // SMTP server port (e.g. 587)
	Username string
	Password string
	From     string // From: address
	To       string // operator address that receives reports
}

// SMTPNotifier emails the operator when a report is filed, via net/smtp
// (PlainAuth + STARTTLS, as smtp.SendMail negotiates). No third-party SDK.
type SMTPNotifier struct {
	cfg SMTPConfig
}

func NewSMTPNotifier(cfg SMTPConfig) *SMTPNotifier {
	return &SMTPNotifier{cfg: cfg}
}

func (n *SMTPNotifier) NotifyNewReport(_ context.Context, r Report) error {
	addr := n.cfg.Host + ":" + n.cfg.Port
	auth := smtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)
	return smtp.SendMail(addr, auth, n.cfg.From, []string{n.cfg.To}, n.buildMessage(r))
}

func (n *SMTPNotifier) buildMessage(r Report) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", n.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", n.cfg.To)
	fmt.Fprintf(&b, "Subject: [NANb] New user report: %s\r\n", r.Reason)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "Report ID:    %s\r\n", r.ID)
	fmt.Fprintf(&b, "Reason:       %s\r\n", r.Reason)
	fmt.Fprintf(&b, "Reported:     %s (%s)\r\n", r.ReportedUsername, r.ReportedAccountID)
	fmt.Fprintf(&b, "Reporter:     %s (device %s)\r\n", r.ReporterAccountID, r.ReporterDeviceID)
	fmt.Fprintf(&b, "Conversation: %s\r\n", r.ConversationID)
	fmt.Fprintf(&b, "Filed at:     %s\r\n", r.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	if strings.TrimSpace(r.Note) != "" {
		fmt.Fprintf(&b, "\r\nNote:\r\n%s\r\n", r.Note)
	}
	if len(r.Messages) > 0 {
		b.WriteString("\r\nForwarded messages (from the reported user):\r\n")
		for _, m := range r.Messages {
			fmt.Fprintf(&b, "  [%s] (%s) %s\r\n", m.SentAt, m.Kind, m.Body)
		}
	}
	return []byte(b.String())
}
