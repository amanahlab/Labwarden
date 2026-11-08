// Package notify sends webhook alerts when scans turn up new serious findings.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/amanahlab/labwarden/server/internal/grype"
	"github.com/amanahlab/labwarden/server/internal/store"
)

// Formats: "json" posts {title, text, content, message, ...}, which Slack,
// Discord, Mattermost, Gotify and generic receivers accept; "ntfy" posts plain
// text with ntfy's Title/Priority/Tags headers.
var Formats = map[string]bool{"json": true, "ntfy": true}

type Config struct {
	URL         string // webhook URL; empty disables notifications. Never logged: it often embeds a secret.
	Format      string // json | ntfy
	MinSeverity string // Critical | High | Medium | Low
	KEV         bool   // also alert on known-exploited findings below MinSeverity
	PublicURL   string // dashboard base URL for links, optional
}

type Notifier struct {
	cfg    Config
	st     *store.Store
	log    *slog.Logger
	client *http.Client
}

func New(cfg Config, st *store.Store, log *slog.Logger) (*Notifier, error) {
	if cfg.Format == "" {
		cfg.Format = "json"
	}
	if !Formats[cfg.Format] {
		return nil, fmt.Errorf("LABWARDEN_NOTIFY_FORMAT must be json or ntfy")
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "Critical"
	}
	cfg.MinSeverity = grype.NormalizeSeverity(cfg.MinSeverity)
	if grype.SeverityRank(cfg.MinSeverity) < grype.SeverityRank("Low") {
		return nil, fmt.Errorf("LABWARDEN_NOTIFY_MIN_SEVERITY must be Critical, High, Medium or Low")
	}
	if cfg.URL != "" {
		u, err := url.Parse(cfg.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("LABWARDEN_NOTIFY_URL must be an http(s) URL")
		}
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	return &Notifier{cfg: cfg, st: st, log: log, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (n *Notifier) Enabled() bool { return n.cfg.URL != "" }

// Status is safe to show in the UI: it never includes the URL.
func (n *Notifier) Status() map[string]any {
	return map[string]any{"enabled": n.Enabled(), "format": n.cfg.Format, "min_severity": n.cfg.MinSeverity, "kev": n.cfg.KEV}
}

// Message is one alert.
type Message struct {
	Title    string
	Lines    []string
	Link     string
	Priority int // 1..5 (ntfy scale)
	Host     string
	Target   string
	Findings []store.NewFinding
}

// Ingested is the store hook: it alerts on new findings that pass the filter.
// It returns at once; delivery happens in the background.
func (n *Notifier) Ingested(m store.IngestMeta, res *store.IngestResult) {
	if !n.Enabled() || len(res.NewFindings) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		msg, ok := n.build(ctx, m.Host, res)
		if !ok {
			return
		}
		if err := n.Send(ctx, msg); err != nil {
			n.log.Warn("notification failed", "host", m.Host, "err", err)
			_ = n.st.AddEvent(ctx, store.Event{Level: "warn", Source: "system", Host: m.Host,
				Message: "notification failed: " + err.Error()})
		}
	}()
}

const maxLines = 10

// Alerting returns the findings worth an alert: at or above MinSeverity, or
// known-exploited when KEV is on, minus anything triaged away. Each
// vulnerability appears once.
func (n *Notifier) Alerting(found []store.NewFinding, suppressed map[string]bool) []store.NewFinding {
	minRank := grype.SeverityRank(n.cfg.MinSeverity)
	seen := map[string]bool{}
	var out []store.NewFinding
	for _, f := range found {
		if seen[f.VulnID] || suppressed[f.VulnID] {
			continue
		}
		if grype.SeverityRank(f.Severity) >= minRank || (n.cfg.KEV && f.KEV) {
			seen[f.VulnID] = true
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		return grype.SeverityRank(out[i].Severity) > grype.SeverityRank(out[j].Severity)
	})
	return out
}

func (n *Notifier) build(ctx context.Context, host string, res *store.IngestResult) (Message, bool) {
	suppressed, err := n.st.SuppressedVulns(ctx, res.HostID)
	if err != nil {
		n.log.Warn("notification: read triage", "err", err)
	}
	hits := n.Alerting(res.NewFindings, suppressed)
	if len(hits) == 0 {
		return Message{}, false
	}
	kev, crit := 0, 0
	for _, f := range hits {
		if f.KEV {
			kev++
		}
		if f.Severity == "Critical" {
			crit++
		}
	}
	noun := "vulnerabilities"
	if len(hits) == 1 {
		noun = "vulnerability"
	}
	msg := Message{
		Title:    fmt.Sprintf("%d new %s on %s", len(hits), noun, host),
		Host:     host,
		Target:   res.Target,
		Findings: hits,
		Priority: 4,
	}
	if kev > 0 || crit > 0 {
		msg.Priority = 5
	}
	msg.Lines = append(msg.Lines, "Target: "+res.Target)
	for i, f := range hits {
		if i == maxLines {
			msg.Lines = append(msg.Lines, fmt.Sprintf("…and %d more", len(hits)-maxLines))
			break
		}
		msg.Lines = append(msg.Lines, line(f))
	}
	if n.cfg.PublicURL != "" {
		msg.Link = fmt.Sprintf("%s/hosts/%d", n.cfg.PublicURL, res.HostID)
	}
	return msg, true
}

func line(f store.NewFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s", f.VulnID, f.Severity)
	if f.KEV {
		b.WriteString(", known exploited")
	}
	fmt.Fprintf(&b, ") in %s %s", f.PkgName, f.PkgVersion)
	if f.FixVersion != "" {
		b.WriteString(", fixed in " + f.FixVersion)
	}
	return b.String()
}

// Test sends a sample alert so the configuration can be checked from the UI.
func (n *Notifier) Test(ctx context.Context) error {
	if !n.Enabled() {
		return errors.New("notifications are not configured (set LABWARDEN_NOTIFY_URL)")
	}
	msg := Message{Title: "LabWarden test notification", Priority: 3,
		Lines: []string{"Notifications are working. You will be alerted about new " + n.cfg.MinSeverity + "+ findings" + map[bool]string{true: " and known-exploited ones.", false: "."}[n.cfg.KEV]}}
	if n.cfg.PublicURL != "" {
		msg.Link = n.cfg.PublicURL
	}
	return n.Send(ctx, msg)
}

// Send delivers one message. Errors never contain the webhook URL.
func (n *Notifier) Send(ctx context.Context, msg Message) error {
	text := strings.Join(msg.Lines, "\n")
	if msg.Link != "" {
		text += "\n" + msg.Link
	}
	var body []byte
	header := http.Header{}
	switch n.cfg.Format {
	case "ntfy":
		body = []byte(text)
		header.Set("Content-Type", "text/plain; charset=utf-8")
		header.Set("Title", msg.Title)
		header.Set("Priority", fmt.Sprint(msg.Priority))
		header.Set("Tags", "rotating_light")
		if msg.Link != "" {
			header.Set("Click", msg.Link)
		}
	default:
		full := "**" + msg.Title + "**\n" + text
		if len(full) > 1900 { // Discord rejects content over 2000 characters
			full = full[:1900] + "…"
		}
		payload := map[string]any{
			"title":   msg.Title,
			"text":    full,
			"content": full,
			"message": text,
			"host":    msg.Host,
			"target":  msg.Target,
			"link":    msg.Link,
		}
		if msg.Findings != nil {
			payload["findings"] = msg.Findings
		}
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return err
		}
		header.Set("Content-Type", "application/json")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid webhook request")
	}
	req.Header = header
	resp, err := n.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // strip the URL, which may embed a secret
			err = ue.Err
		}
		return fmt.Errorf("webhook request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
