// Command go-chi is an API protected by github.com/madappgang/passflow-go/auth on the Chi router.
// The React client and scripts/api-check.sh next door call it. See README.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/madappgang/passflow-go/auth"
)

const shutdownTimeout = 5 * time.Second

type settings struct {
	issuer        string
	audience      string
	jwksURL       string
	allowedOrigin string
	exposeHeader  bool
	freshMaxAge   time.Duration
	port          string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadSettings()
	if err != nil {
		return err
	}
	verifier, err := auth.NewVerifier(auth.Config{
		Issuer:    cfg.issuer,
		Audiences: []string{cfg.audience},
		JWKSURL:   cfg.jwksURL,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           newRouter(verifier, cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		shutdownDone <- server.Shutdown(shutdownCtx)
	}()

	log.Printf("go-chi example on :%s, CORS origin %s, expose challenge %t", cfg.port, cfg.allowedOrigin, cfg.exposeHeader)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-shutdownDone
}

func loadSettings() (settings, error) {
	cfg := settings{
		issuer:        os.Getenv("PASSFLOW_ISSUER"),
		audience:      os.Getenv("PASSFLOW_AUDIENCE"),
		jwksURL:       os.Getenv("PASSFLOW_JWKS_URL"),
		allowedOrigin: envOr("ALLOWED_ORIGIN", "http://localhost:5173"),
		exposeHeader:  os.Getenv("EXPOSE_CHALLENGE_HEADER") != "false",
		port:          envOr("PORT", "8081"),
	}
	if cfg.issuer == "" {
		return cfg, errors.New("PASSFLOW_ISSUER is required")
	}
	if cfg.audience == "" {
		return cfg, errors.New("PASSFLOW_AUDIENCE is required")
	}
	seconds, err := strconv.Atoi(envOr("FRESH_MAX_AGE", "300"))
	if err != nil || seconds < 1 {
		return cfg, errors.New("FRESH_MAX_AGE must be a whole number of seconds, at least 1")
	}
	cfg.freshMaxAge = time.Duration(seconds) * time.Second
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func newRouter(verifier *auth.Verifier, cfg settings) http.Handler {
	options := cors.Options{
		AllowedOrigins:   []string{cfg.allowedOrigin},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}
	// Off is the negative case the browser run needs: the SDK must warn and recover, not sign out.
	if cfg.exposeHeader {
		options.ExposedHeaders = auth.CORSExposedHeaders()
	}

	r := chi.NewRouter()
	// CORS comes first, so that a preflight never reaches authentication and a rejection still
	// carries the CORS headers.
	r.Use(cors.Handler(options))

	r.Get("/public", public)

	// The composable form: one verifier upstream, then checks on the claims it produced.
	r.Group(func(r chi.Router) {
		r.Use(verifier.Authenticate)
		r.Get("/me", me)
		r.With(auth.Require(auth.AAL2)).Get("/invoices", invoices)
	})

	// The one-line form: the verifier's own method authenticates on demand.
	r.With(verifier.RequireFresh(cfg.freshMaxAge)).Post("/transfers", transfers)

	return r
}

func public(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"public": true})
}

func me(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims in context", http.StatusInternalServerError)
		return
	}
	roles := make(map[string][]string, len(claims.Tenants))
	for tenantID := range claims.Tenants {
		roles[tenantID] = claims.Roles(tenantID)
	}
	writeJSON(w, map[string]any{
		"sub":       claims.Subject,
		"acr":       claims.ACR.String(),
		"amr":       claims.AMR,
		"auth_time": unixOrNil(claims.AuthTime),
		"roles":     roles,
	})
}

func invoices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims in context", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"invoices": []string{}, "acr": claims.ACR.String()})
}

func transfers(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims in context", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"transferred": true, "auth_time": unixOrNil(claims.AuthTime)})
}

func unixOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write response: %v", err)
	}
}
