package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// Event is a notification emitted by Qorvex.
type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      string            `json:"type"`        // check.completed, check.failed, risk.critical, secret.found, scan.started
	Severity  string            `json:"severity"`    // low, medium, high, critical
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	ProjectID string            `json:"project_id,omitempty"`
	CheckID   string            `json:"check_id,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Notifier delivers events to a destination.
type Notifier interface {
	Notify(ctx context.Context, ev Event) error
	Name() string
}

// MultiNotifier fans out events to several notifiers.
type MultiNotifier struct {
	notifiers []Notifier
	mu        sync.RWMutex
}

func NewMultiNotifier() *MultiNotifier {
	return &MultiNotifier{}
}

func (m *MultiNotifier) Add(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers = append(m.notifiers, n)
}

func (m *MultiNotifier) Notify(ctx context.Context, ev Event) error {
	m.mu.RLock()
	targets := make([]Notifier, len(m.notifiers))
	copy(targets, m.notifiers)
	m.mu.RUnlock()

	var firstErr error
	for _, n := range targets {
		if err := n.Notify(ctx, ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiNotifier) Name() string {
	return "multi"
}

// WebhookNotifier posts events as JSON to an HTTP endpoint.
type WebhookNotifier struct {
	url     string
	token   string
	client  *http.Client
	headers map[string]string
}

func NewWebhookNotifier(url, token string) *WebhookNotifier {
	return &WebhookNotifier{
		url:     url,
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
		headers: map[string]string{},
	}
}

func (w *WebhookNotifier) WithHeader(key, value string) *WebhookNotifier {
	w.headers[key] = value
	return w
}

func (w *WebhookNotifier) Notify(ctx context.Context, ev Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "qorvex-notifier/1.0")
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook %s returned %d: %s", w.url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (w *WebhookNotifier) Name() string {
	return "webhook:" + w.url
}

// EmailNotifier delivers events via SMTP.
type EmailNotifier struct {
	host     string
	port   int
	user   string
	pass   string
	from   string
	to     []string
	auth   smtp.Auth
}

func NewEmailNotifier(host string, port int, user, pass, from string, to ...string) *EmailNotifier {
	if port <= 0 {
		port = 25
	}
	var auth smtp.Auth
	if user != "" && pass != "" {
		auth = smtp.PlainAuth("", user, pass, host)
	}
	return &EmailNotifier{
		host: host,
		port: port,
		user: user,
		pass: pass,
		from: from,
		to:   to,
		auth: auth,
	}
}

func (e *EmailNotifier) Notify(ctx context.Context, ev Event) error {
	_ = ctx

	subject := fmt.Sprintf("Qorvex: [%s] %s", strings.ToUpper(ev.Severity), ev.Title)
	body := fmt.Sprintf(
		"Qorvex notification\n\nType: %s\nSeverity: %s\nTitle: %s\nMessage: %s\nProject: %s\nCheck: %s\nTime: %s\n",
		ev.Type, ev.Severity, ev.Title, ev.Message, ev.ProjectID, ev.CheckID, ev.Timestamp.UTC().String(),
	)

	msg := []byte("From: " + e.from + "\r\n" +
		"To: " + strings.Join(e.to, ",") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		body)

	recipients := e.to
	if len(recipients) == 0 {
		recipients = []string{e.from}
	}
	return smtp.SendMail(fmt.Sprintf("%s:%d", e.host, e.port), e.auth, e.from, recipients, msg)
}

func (e *EmailNotifier) Name() string {
	return "email:" + strings.Join(e.to, ",")
}

// SlackNotifier posts events to a Slack incoming webhook.
type SlackNotifier struct {
	url     string
	channel string
	username string
	client  *http.Client
}

func NewSlackNotifier(url, channel string) *SlackNotifier {
	return &SlackNotifier{
		url:      url,
		channel:  channel,
		username: "qorvex",
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackNotifier) Notify(ctx context.Context, ev Event) error {
	color := "#36a64f"
	switch strings.ToLower(ev.Severity) {
	case "critical":
		color = "#ff0000"
	case "high":
		color = "#ff9900"
	case "medium":
		color = "#ffcc00"
	case "low":
		color = "#36a64f"
	default:
		color = "#cccccc"
	}

	msg := map[string]interface{}{
		"channel":   s.channel,
		"username":  s.username,
		"icon_emoji": ":bell:",
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": ev.Title,
				"text":  ev.Message,
				"fields": []map[string]interface{}{
					{"title": "Type", "value": ev.Type, "short": true},
					{"title": "Severity", "value": ev.Severity, "short": true},
					{"title": "Project", "value": ev.ProjectID, "short": true},
					{"title": "Check", "value": ev.CheckID, "short": true},
				},
				"footer": "Qorvex",
				"ts":     ev.Timestamp.Unix(),
			},
		},
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

func (s *SlackNotifier) Name() string {
	return "slack:" + s.channel
}

// SeverityRouter routes events based on severity thresholds.
type SeverityRouter struct {
	notifiers map[string]Notifier
	defaultNotifier Notifier
	mu sync.RWMutex
	threshold map[string]int
}

var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func NewSeverityRouter() *SeverityRouter {
	return &SeverityRouter{
		notifiers:     map[string]Notifier{},
		threshold:     map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4},
	}
}

func (r *SeverityRouter) Register(severity string, n Notifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifiers[strings.ToLower(severity)] = n
}

func (r *SeverityRouter) SetDefault(n Notifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultNotifier = n
}

func (r *SeverityRouter) Notify(ctx context.Context, ev Event) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rank, ok := severityRank[strings.ToLower(ev.Severity)]
	if !ok {
		rank = 1
	}

	var targets []Notifier
	for sev, n := range r.notifiers {
		if severityRank[sev] >= rank {
			targets = append(targets, n)
		}
	}
	if len(targets) == 0 && r.defaultNotifier != nil {
		targets = append(targets, r.defaultNotifier)
	}

	var firstErr error
	for _, n := range targets {
		if err := n.Notify(ctx, ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *SeverityRouter) Name() string {
	return "severity-router"
}

// NoopNotifier discards events (useful in tests / disabled mode).
type NoopNotifier struct{}

func (NoopNotifier) Notify(ctx context.Context, ev Event) error { return nil }
func (NoopNotifier) Name() string { return "noop" }

// ConsoleNotifier prints events to stdout.
type ConsoleNotifier struct{}

func (ConsoleNotifier) Notify(ctx context.Context, ev Event) error {
	fmt.Printf("[Qorvex] %s [%s] %s: %s\n", ev.Timestamp.UTC().Format(time.RFC3339), ev.Severity, ev.Title, ev.Message)
	return nil
}

func (ConsoleNotifier) Name() string { return "console" }
