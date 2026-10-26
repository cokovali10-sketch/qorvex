package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"qorvex/pkg/api"
	"qorvex/pkg/audit"
	"qorvex/pkg/orchestrator"
	"qorvex/pkg/policy"
	"qorvex/pkg/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Qorvex v0.2.0 — AI Code Verification Platform")
	log.Println("Build. Test. Verify.")

	s := store.New()
	auditor := audit.NewLogger("qorvex-secret-dev-key-change-in-production", 10000)
	pe := policy.NewEngine()
	orch := orchestrator.NewOrchestrator(s)
	orch.SetAuditor(auditor)

	server := api.NewServer(s, auditor, pe, orch)

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down Qorvex...")
		os.Exit(0)
	}()

	addr := ":8420"
	if envPort := os.Getenv("QORVEX_PORT"); envPort != "" {
		addr = ":" + envPort
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Qorvex Platform v0.2.0")
	fmt.Println("  API:  http://localhost" + addr)
	fmt.Println("  Docs: http://localhost" + addr + "/api/v1/health")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if err := server.Start(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
