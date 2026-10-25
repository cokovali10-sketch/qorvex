package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"qorvex/pkg/platform"
)

// Logger provides an immutable, signed audit log.
type Logger struct {
	mu       sync.RWMutex
	entries  []*platform.AuditEntry
	secret   []byte
	maxLimit int
}

// NewLogger creates an audit logger with signing.
func NewLogger(secret string, maxEntries int) *Logger {
	return &Logger{
		entries:  make([]*platform.AuditEntry, 0, 1024),
		secret:   []byte(secret),
		maxLimit: maxEntries,
	}
}

// Append adds an entry, signs it, and stores it.
func (l *Logger) Append(entry *platform.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now().UTC()
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("qaud-%d-%x", entry.Timestamp.UnixNano(), len(l.entries)+1)
	}

	// Build HMAC signature
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		entry.ID, entry.Actor, entry.Action, entry.ResourceID, entry.Detail, entry.Timestamp.UnixNano())
	mac := hmac.New(sha256.New, l.secret)
	mac.Write([]byte(data))
	entry.Signature = hex.EncodeToString(mac.Sum(nil))

	l.entries = append(l.entries, entry)

	// Enforce max limit
	if len(l.entries) > l.maxLimit {
		l.entries = l.entries[len(l.entries)-l.maxLimit:]
	}
	return nil
}

// List returns the last n entries.
func (l *Logger) List(n int) ([]*platform.AuditEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	total := len(l.entries)
	if n <= 0 || n > total {
		n = total
	}
	res := make([]*platform.AuditEntry, n)
	copy(res, l.entries[total-n:])
	return res, nil
}

// Verify checks the HMAC signature of an entry.
func (l *Logger) Verify(entry *platform.AuditEntry) (bool, error) {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%d",
		entry.ID, entry.Actor, entry.Action, entry.ResourceID, entry.Detail, entry.Timestamp.UnixNano())
	mac := hmac.New(sha256.New, l.secret)
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(entry.Signature), []byte(expected)), nil
}

// VerifyAll checks the integrity of all stored entries.
func (l *Logger) VerifyAll() (bool, []string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var invalid []string
	for _, e := range l.entries {
		ok, err := l.Verify(e)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			invalid = append(invalid, e.ID)
		}
	}
	return len(invalid) == 0, invalid, nil
}

// GetStats returns audit log statistics.
func (l *Logger) GetStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()
	stats := map[string]interface{}{
		"total_entries":  len(l.entries),
		"max_entries":    l.maxLimit,
		"capacity_used":  fmt.Sprintf("%.1f%%", float64(len(l.entries))/float64(l.maxLimit)*100),
	}
	return stats
}