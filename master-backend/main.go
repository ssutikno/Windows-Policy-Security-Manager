package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/user/wwpo/master-backend/db"
	"github.com/user/wwpo/master-backend/handlers"
)

//go:embed all:dist
var frontendFS embed.FS

// Simple CORS middleware to allow React UI communication
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

func main() {
	// Parse CLI flags
	genTokenWorkgroup := flag.String("gentoken", "", "Generate a new setup token for the specified Workgroup and exit")
	tokenDuration := flag.Int("duration", 120, "Duration of the generated setup token in minutes")
	flag.Parse()

	// 1. Initialize SQLite Database
	dbPath := "./wwpo.db"
	log.Printf("Initializing SQLite database at %s...", dbPath)
	err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	// CLI Token Generator mode
	if *genTokenWorkgroup != "" {
		token, err := db.GenerateSetupToken(*genTokenWorkgroup, *tokenDuration)
		if err != nil {
			fmt.Printf("Error generating token: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n--- WWPO SETUP TOKEN GENERATED ---\n")
		fmt.Printf("Workgroup: %s\n", token.Workgroup)
		fmt.Printf("Token Value: %s\n", token.Value)
		fmt.Printf("Expires At: %s\n", token.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("----------------------------------\n\n")
		os.Exit(0)
	}

	log.Println("SQLite database schema initialized successfully.")

	// 2. Setup REST HTTP Handlers
	http.HandleFunc("/api/v1/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

	http.HandleFunc("/api/v1/enroll", corsMiddleware(handlers.EnrollAgentHandler))
	http.HandleFunc("/api/v1/tokens", corsMiddleware(handlers.GenerateTokenHandler))
	http.HandleFunc("/api/v1/connect", handlers.ConnectWebSocketHandler)
	http.HandleFunc("/api/v1/agents", corsMiddleware(handlers.ListAgentsHandler))
	http.HandleFunc("/api/v1/events", corsMiddleware(handlers.ListEventsHandler))
	http.HandleFunc("/api/v1/policies", corsMiddleware(handlers.DeployPolicyHandler))
	http.HandleFunc("/api/v1/policies/latest", corsMiddleware(handlers.GetPolicyHandler))

	// 3. Serve embedded Frontend WebUI
	subFS, err := fs.Sub(frontendFS, "dist")
	if err != nil {
		log.Fatalf("Failed to create sub FS: %v", err)
	}
	fileServer := http.FileServer(http.FS(subFS))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		_, err := subFS.Open(path)
		if err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})

	// 4. Start Server Listen Loop
	port := ":8080"
	log.Printf("WWPO Master control server listening on %s...", port)
	err = http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}
