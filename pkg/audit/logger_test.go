package audit

import (
	"testing"

	"qorvex/pkg/platform"
)

func TestNewLogger(t *testing.T) {
	l := NewLogger("secret", 1000)
	if l == nil {
		t.Fatal("logger should not be nil")
	}
	stats := l.GetStats()
	if stats["total_entries"].(int) != 0 {
		t.Errorf("expected 0 entries, got %d", stats["total_entries"])
	}
}

func TestAppend(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	entry := &platform.AuditEntry{
		Actor:      "test",
		Action:     "test.action",
		ResourceID: "res-1",
		Detail:     "test detail",
	}
	err := l.Append(entry)
	if err != nil {
		t.Errorf("append failed: %v", err)
	}
	if entry.ID == "" {
		t.Error("ID should be set")
	}
	if entry.Signature == "" {
		t.Error("signature should be set")
	}
	if entry.Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
}

func TestVerifyValid(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	entry := &platform.AuditEntry{
		Actor:      "test",
		Action:     "test.action",
		ResourceID: "res-1",
		Detail:     "test detail",
	}
	l.Append(entry)

	valid, err := l.Verify(entry)
	if err != nil {
		t.Errorf("verify failed: %v", err)
	}
	if !valid {
		t.Error("signature should be valid")
	}
}

func TestVerifyTampered(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	entry := &platform.AuditEntry{
		Actor:      "test",
		Action:     "test.action",
		ResourceID: "res-1",
		Detail:     "test detail",
	}
	l.Append(entry)

	entry.Detail = "tampered content"
	valid, err := l.Verify(entry)
	if err != nil {
		t.Errorf("verify failed: %v", err)
	}
	if valid {
		t.Error("signature should be invalid after tampering")
	}
}

func TestVerifyAllValid(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	entries := []*platform.AuditEntry{
		{Actor: "user1", Action: "create", ResourceID: "1", Detail: "first"},
		{Actor: "user2", Action: "update", ResourceID: "2", Detail: "second"},
	}
	for _, e := range entries {
		l.Append(e)
	}

	valid, invalid, err := l.VerifyAll()
	if err != nil {
		t.Errorf("verify all failed: %v", err)
	}
	if !valid {
		t.Errorf("all should be valid, invalid: %v", invalid)
	}
}

func TestVerifyAllWithInvalid(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	entry := &platform.AuditEntry{
		Actor:      "user1",
		Action:     "create",
		ResourceID: "1",
		Detail:     "first",
	}
	l.Append(entry)

	// Tamper directly in the logger's internal storage
	l.mu.Lock()
	l.entries[0].Detail = "tampered"
	l.mu.Unlock()

	valid, invalid, _ := l.VerifyAll()
	if valid {
		t.Error("expected invalid after tampering")
	}
	if len(invalid) != 1 {
		t.Errorf("expected 1 invalid, got %d", len(invalid))
	}
}

func TestListLimit(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	for i := 0; i < 10; i++ {
		l.Append(&platform.AuditEntry{
			Actor: "test", Action: "action", ResourceID: "r", Detail: "d",
		})
	}

	entries, err := l.List(5)
	if err != nil {
		t.Errorf("list failed: %v", err)
	}
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}

	// List with 0 limit returns all
	all, _ := l.List(0)
	if len(all) != 10 {
		t.Errorf("expected 10 entries, got %d", len(all))
	}
}

func TestMaxLimit(t *testing.T) {
	l := NewLogger("test-secret", 3)
	for i := 0; i < 10; i++ {
		l.Append(&platform.AuditEntry{
			Actor: "test", Action: "action", ResourceID: "r", Detail: "d",
		})
	}
	entries, _ := l.List(100)
	if len(entries) > 3 {
		t.Errorf("expected at most 3 entries, got %d", len(entries))
	}
}

func TestDifferentSecrets(t *testing.T) {
	l1 := NewLogger("secret1", 1000)
	l2 := NewLogger("secret2", 1000)

	entry := &platform.AuditEntry{
		Actor: "test", Action: "action", ResourceID: "r", Detail: "d",
	}
	l1.Append(entry)

	valid, _ := l2.Verify(entry)
	if valid {
		t.Error("entry signed with different secret should not verify")
	}
}

func TestStats(t *testing.T) {
	l := NewLogger("test-secret", 500)
	l.Append(&platform.AuditEntry{Actor: "a", Action: "a", ResourceID: "r", Detail: "d"})
	l.Append(&platform.AuditEntry{Actor: "b", Action: "b", ResourceID: "r", Detail: "d"})

	stats := l.GetStats()
	if stats["total_entries"].(int) != 2 {
		t.Errorf("expected 2 entries, got %d", stats["total_entries"])
	}
	if stats["max_entries"].(int) != 500 {
		t.Errorf("expected 500 max, got %d", stats["max_entries"])
	}
}

func TestConcurrentAppend(t *testing.T) {
	l := NewLogger("test-secret", 1000)
	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 25; i++ {
			l.Append(&platform.AuditEntry{Actor: "a", Action: "a", ResourceID: "r", Detail: "d"})
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 25; i++ {
			l.Append(&platform.AuditEntry{Actor: "b", Action: "b", ResourceID: "r", Detail: "d"})
		}
		done <- true
	}()

	<-done
	<-done

	stats := l.GetStats()
	if stats["total_entries"].(int) > 100 {
		t.Errorf("expected at most 100 entries, got %d", stats["total_entries"])
	}
}
