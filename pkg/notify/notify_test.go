package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testEvent() Event {
	return Event{
		ID:        "evt-1",
		Type:      "check.completed",
		Severity:  "high",
		Title:     "Check finished",
		Message:   "Pipeline passed",
		ProjectID: "proj-1",
		CheckID:   "chk-1",
		Meta:      map[string]string{"engine": "forge"},
	}
}

func TestMultiNotifierFansOut(t *testing.T) {
	calls := 0
	n := &countingNotifier{&calls}
	m := NewMultiNotifier()
	m.Add(n)
	m.Add(n)

	if err := m.Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
}

func TestWebhookNotifierPostsJSON(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		got = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	w := NewWebhookNotifier(srv.URL, "tok").WithHeader("X-App", "qorvex")
	if err := w.Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"title":"Check finished"`) {
		t.Fatalf("unexpected payload: %s", got)
	}
	if !strings.Contains(got, `"severity":"high"`) {
		t.Fatalf("missing severity: %s", got)
	}
}

func TestWebhookNotifierErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	w := NewWebhookNotifier(srv.URL, "")
	if err := w.Notify(context.Background(), testEvent()); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestSeverityRouterRoutes(t *testing.T) {
	highCalls := 0
	lowCalls := 0
	highN := &countingNotifier{&highCalls}
	lowN := &countingNotifier{&lowCalls}

	r := NewSeverityRouter()
	r.Register("high", highN)
	r.Register("critical", highN)
	r.Register("low", lowN)

	ev := testEvent()
	ev.Severity = "critical"
	if err := r.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if highCalls != 1 {
		t.Fatalf("expected 1 high-severity call, got %d", highCalls)
	}

	ev.Severity = "low"
	if err := r.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if lowCalls != 1 {
		t.Fatalf("expected 1 low-severity call, got %d", lowCalls)
	}
}

type countingNotifier struct {
	calls *int
}

func (c *countingNotifier) Notify(context.Context, Event) error {
	*c.calls++
	return nil
}
func (c *countingNotifier) Name() string { return "count" }
