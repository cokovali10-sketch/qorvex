package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"qorvex/pkg/audit"
	"qorvex/pkg/orchestrator"
	"qorvex/pkg/platform"
	"qorvex/pkg/policy"
	"qorvex/pkg/report"
	"qorvex/pkg/store"
)

// Role represents user roles.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// Claims represents JWT claims with role.
type Claims struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
	jwt.RegisteredClaims
}

// Server is the REST API server for Qorvex.
type Server struct {
	store         *store.Store
	auditor       *audit.Logger
	policyEngine  *policy.Engine
	orchestrator  *orchestrator.Orchestrator
	mux           *http.ServeMux
	jwtSecret     []byte
}

func NewServer(s *store.Store, al *audit.Logger, pe *policy.Engine, o *orchestrator.Orchestrator, jwtSecret string) *Server {
	sv := &Server{
		store:         s,
		auditor:       al,
		policyEngine:  pe,
		orchestrator:  o,
		jwtSecret:     []byte(jwtSecret),
	}
	sv.setupRoutes()
	return sv
}

func (s *Server) setupRoutes() {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Protected routes with auth
	mux.Handle("GET /api/v1/projects", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleListProjects))))
	mux.Handle("POST /api/v1/projects", s.withAuth(s.withRole(RoleAdmin)(http.HandlerFunc(s.handleCreateProject))))
	mux.Handle("GET /api/v1/projects/{id}", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleGetProject))))

	mux.Handle("POST /api/v1/projects/{id}/checks", s.withAuth(s.withRole(RoleAdmin)(http.HandlerFunc(s.handleStartCheck))))
	mux.Handle("GET /api/v1/checks/{id}", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleGetCheck))))
	mux.Handle("GET /api/v1/projects/{id}/checks", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleListChecks))))

	mux.Handle("GET /api/v1/projects/{id}/findings", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleListFindings))))

	// Export endpoint
	mux.Handle("GET /api/v1/checks/{id}/export", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleExportCheck))))

	mux.Handle("GET /api/v1/policies", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleListPolicies))))
	mux.Handle("POST /api/v1/policies", s.withAuth(s.withRole(RoleAdmin)(http.HandlerFunc(s.handleSavePolicy))))
	mux.Handle("GET /api/v1/policies/{id}", s.withAuth(s.withRole(RoleViewer, RoleAdmin)(http.HandlerFunc(s.handleGetPolicy))))

	mux.Handle("GET /api/v1/audit", s.withAuth(s.withRole(RoleAdmin)(http.HandlerFunc(s.handleListAudit))))
	mux.Handle("GET /api/v1/audit/verify", s.withAuth(s.withRole(RoleAdmin)(http.HandlerFunc(s.handleVerifyAudit))))
	mux.Handle("GET /api/v1/audit/stats", s.withAuth(s.withRole(RoleAdmin)(http.HandlerFunc(s.handleAuditStats))))

	s.mux = mux
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// ---- Handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.2.0"})
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.orchestrator.ListProjects()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	project, err := s.orchestrator.CreateProject(req.Name, req.Path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The orchestrator already records project.create in the signed audit log.
	writeJSON(w, http.StatusCreated, project)
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	project, err := s.store.GetProject(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *Server) handleStartCheck(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	run, err := s.orchestrator.StartCheck(projectID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) handleGetCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := s.orchestrator.GetCheckStatus(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleListChecks(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	checks, err := s.orchestrator.ListChecks(projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, checks)
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	findings, err := s.store.GetFindings(projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.policyEngine.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	var p platform.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy")
		return
	}
	if err := s.policyEngine.Save(&p); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.auditor.Append(&platform.AuditEntry{
		Actor:      "user",
		Action:     "policy.save",
		ResourceID: p.ID,
		Detail:     p.Name,
	})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.policyEngine.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.auditor.List(100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	valid, invalid, err := s.auditor.VerifyAll()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   valid,
		"invalid": invalid,
	})
}

func (s *Server) handleAuditStats(w http.ResponseWriter, r *http.Request) {
	stats := s.auditor.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message, "status": fmt.Sprintf("%d %s", status, http.StatusText(status))})
}

// Start launches the HTTP server.
func (s *Server) Start(addr string) error {
	log.Printf("Qorvex API server starting on %s", addr)
	return http.ListenAndServe(addr, withCORS(s))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:], true
	}
	return "", false
}

// withAuth validates JWT and passes claims to handler.
func (s *Server) withAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr, ok := extractBearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return s.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withRole restricts access to specified roles.
func (s *Server) withRole(roles ...Role) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("claims").(*Claims)
			if !ok {
				writeError(w, http.StatusForbidden, "missing claims")
				return
			}
			for _, role := range roles {
				if claims.Role == role {
					h.ServeHTTP(w, r)
					return
				}
			}
			writeError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

// handleExportCheck exports a check run report in specified format (json, sarif, html).
func (s *Server) handleExportCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	run, err := s.orchestrator.GetCheckStatus(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "check not found")
		return
	}

	data, err := report.Format(format, run)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case "sarif":
		w.Header().Set("Content-Type", "application/sarif+json")
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
