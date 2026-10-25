package store

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"qorvex/pkg/platform"
)

// Store provides an in-memory storage for development.
// Production replaces with PostgreSQL via the same interface.
type Store struct {
	mu       sync.RWMutex
	projects map[string]*platform.Project
	checks   map[string]*platform.CheckRun
	findings map[string]*platform.Finding
	audit    []*platform.AuditEntry
	counter  atomic.Int64
}

func New() *Store {
	return &Store{
		projects: make(map[string]*platform.Project),
		checks:   make(map[string]*platform.CheckRun),
		findings: make(map[string]*platform.Finding),
		audit:    make([]*platform.AuditEntry, 0),
	}
}

func (s *Store) CreateProject(p *platform.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.ID = fmt.Sprintf("proj-%d-%d", time.Now().UnixMilli(), s.counter.Add(1))
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	s.projects[p.ID] = p
	return nil
}

func (s *Store) GetProject(id string) (*platform.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	if !ok {
		return nil, fmt.Errorf("project not found: %s", id)
	}
	return p, nil
}

func (s *Store) ListProjects() ([]*platform.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*platform.Project, 0, len(s.projects))
	for _, p := range s.projects {
		res = append(res, p)
	}
	return res, nil
}

func (s *Store) CreateCheckRun(r *platform.CheckRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ID = fmt.Sprintf("chk-%d-%d", time.Now().UnixMilli(), s.counter.Add(1))
	r.StartTime = time.Now()
	r.Status = "pending"
	s.checks[r.ID] = r
	return nil
}

func (s *Store) GetCheckRun(id string) (*platform.CheckRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.checks[id]
	if !ok {
		return nil, fmt.Errorf("check run not found: %s", id)
	}
	return r, nil
}

func (s *Store) UpdateCheckRun(r *platform.CheckRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.checks[r.ID]; !ok {
		return fmt.Errorf("check run not found: %s", r.ID)
	}
	s.checks[r.ID] = r
	return nil
}

func (s *Store) ListCheckRuns(projectID string) ([]*platform.CheckRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var res []*platform.CheckRun
	for _, r := range s.checks {
		if r.ProjectID == projectID {
			res = append(res, r)
		}
	}
	return res, nil
}

func (s *Store) CreateFinding(f *platform.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.ID = fmt.Sprintf("fnd-%d-%d", time.Now().UnixMilli(), s.counter.Add(1))
	s.findings[f.ID] = f
	return nil
}

func (s *Store) GetFindings(projectID string) ([]*platform.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var res []*platform.Finding
	for _, f := range s.findings {
		if f.ProjectID == projectID {
			res = append(res, f)
		}
	}
	return res, nil
}

func (s *Store) AppendAudit(entry *platform.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.Timestamp = time.Now()
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("aud-%d-%d", time.Now().UnixMilli(), s.counter.Add(1))
	}
	s.audit = append(s.audit, entry)
	return nil
}

func (s *Store) ListAudit(limit int) ([]*platform.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.audit)
	if limit > 0 && limit < n {
		n = limit
	}
	return s.audit[len(s.audit)-n:], nil
}