package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"qorvex/pkg/audit"
	"qorvex/pkg/orchestrator"
	"qorvex/pkg/platform"
	"qorvex/pkg/policy"
	"qorvex/pkg/store"
)

func testToken(role Role) string {
	claims := Claims{
		Username: "testuser",
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte("test-jwt-secret"))
	return signed
}

func newTestServer(t *testing.T) (*Server, *store.Store, *audit.Logger) {
	t.Helper()
	s := store.New()
	al := audit.NewLogger("test-secret", 1000)
	pe := policy.NewEngine()
	orch := orchestrator.NewOrchestrator(s)
	orch.SetAuditor(al)
	return NewServer(s, al, pe, orch, "test-jwt-secret"), s, al
}

func doRequest(t *testing.T, srv *Server, method, path string, body any, role Role) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(role))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := doRequest(t, srv, http.MethodGet, "/api/v1/health", nil, RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected ok, got %q", body["status"])
	}
}

func TestCreateProjectRequiresName(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := doRequest(t, srv, http.MethodPost, "/api/v1/projects", map[string]string{"path": "."}, RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateProject(t *testing.T) {
	srv, s, al := newTestServer(t)
	dir := t.TempDir()

	rec := doRequest(t, srv, http.MethodPost, "/api/v1/projects", map[string]string{
		"name": "demo",
		"path": dir,
	}, RoleAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var project platform.Project
	if err := json.Unmarshal(rec.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	if project.ID == "" || project.Name != "demo" {
		t.Errorf("unexpected project: %+v", project)
	}

	projects, _ := s.ListProjects()
	if len(projects) != 1 {
		t.Errorf("expected 1 project, got %d", len(projects))
	}

	entries, _ := al.List(10)
	found := false
	for _, e := range entries {
		if e.Action == "project.create" && e.ResourceID == project.ID {
			found = true
		}
	}
	if !found {
		t.Error("project.create should be written to the signed audit log")
	}
}

func TestGetProjectNotFound(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := doRequest(t, srv, http.MethodGet, "/api/v1/projects/missing", nil, RoleViewer)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestStartCheckInvalidPath(t *testing.T) {
	srv, s, _ := newTestServer(t)

	p := &platform.Project{Name: "missing", Path: filepath.Join(t.TempDir(), "does-not-exist")}
	if err := s.CreateProject(p); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(t, srv, http.MethodPost, "/api/v1/projects/"+p.ID+"/checks", nil, RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid project path, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStartCheckAccepted(t *testing.T) {
	srv, s, _ := newTestServer(t)
	dir := t.TempDir()

	p := &platform.Project{Name: "valid", Path: dir}
	if err := s.CreateProject(p); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(t, srv, http.MethodPost, "/api/v1/projects/"+p.ID+"/checks", nil, RoleAdmin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var run platform.CheckRun
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.ID == "" || run.ProjectID != p.ID {
		t.Errorf("unexpected check run: %+v", run)
	}
}

func TestListPolicies(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := doRequest(t, srv, http.MethodGet, "/api/v1/policies", nil, RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var policies []platform.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &policies); err != nil {
		t.Fatal(err)
	}
	if len(policies) == 0 {
		t.Error("expected the default policy")
	}
}

func TestSaveAndGetPolicy(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := doRequest(t, srv, http.MethodPost, "/api/v1/policies", map[string]any{
		"name": "strict",
		"rules": []map[string]string{
			{"id": "block-high", "severity": "block", "category": "security", "pattern": "high|critical", "description": "block high"},
		},
	}, RoleAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var p platform.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	rec = doRequest(t, srv, http.MethodGet, "/api/v1/policies/"+p.ID, nil, RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuditVerify(t *testing.T) {
	srv, _, al := newTestServer(t)
	if err := al.Append(&platform.AuditEntry{Actor: "user", Action: "test", ResourceID: "r1", Detail: "d"}); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(t, srv, http.MethodGet, "/api/v1/audit/verify", nil, RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		Valid   bool     `json:"valid"`
		Invalid []string `json:"invalid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Valid {
		t.Errorf("expected valid audit log, invalid=%v", body.Invalid)
	}
}

func TestCORSHeaders(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	withCORS(srv).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("unexpected CORS origin: %q", got)
	}
}

func TestWriteErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "bad input")
	if !strings.Contains(rec.Body.String(), `"error":"bad input"`) {
		t.Errorf("unexpected error body: %s", rec.Body.String())
	}
}
