package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TrippingKelsea/nebula-starcaller/internal/archive/sqlite"
	"github.com/TrippingKelsea/nebula-starcaller/internal/auth"
	"github.com/TrippingKelsea/nebula-starcaller/internal/bundle"
	"github.com/TrippingKelsea/nebula-starcaller/internal/ca"
	"github.com/TrippingKelsea/nebula-starcaller/internal/cert"
	"github.com/TrippingKelsea/nebula-starcaller/internal/config"
	"github.com/TrippingKelsea/nebula-starcaller/internal/nebulax"
	"github.com/TrippingKelsea/nebula-starcaller/internal/server"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
	"github.com/TrippingKelsea/nebula-starcaller/web"
)

func main() {
	configPath := flag.String("config", os.Getenv("STARCALLER_CONFIG"), "path to config.yml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("mkdir data_dir: %v", err)
	}

	s, err := storesqlite.Open(cfg.DBPath())
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer s.Close()
	arch := sqlite.New(s.DB())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := auth.EnsureBootstrap(ctx, s, cfg.Bootstrap); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	runner := &nebulax.Real{Binary: cfg.NebulaCert}
	casvc := &ca.Service{Store: s, Archive: arch, Runner: runner}
	b := &bundle.Builder{Binaries: bundle.DirProvider{Root: cfg.BinariesDir}}
	certsvc := &cert.Service{Store: s, Archive: arch, Runner: runner, CAService: casvc, Bundle: b}

	sessions := auth.NewSessionManager(s, cfg.CookieName, cfg.SessionTTL, !cfg.DevMode)

	waSvc, err := auth.NewWebAuthnService(cfg.WebAuthn, s)
	if err != nil {
		log.Printf("webauthn: %v — WebAuthn will be disabled", err)
	}

	srv, err := server.New(&server.Server{
		Store: s, Sessions: sessions, CA: casvc, Cert: certsvc, WebAuthn: waSvc,
	}, server.Assets{Templates: web.Templates, Static: web.Static})
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Periodic expired-session cleanup
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = s.DeleteExpiredSessions(ctx)
			}
		}
	}()

	go func() {
		log.Printf("nebula-starcaller listening on %s", cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	shutdownCtx, sc := context.WithTimeout(context.Background(), 10*time.Second)
	defer sc()
	_ = httpSrv.Shutdown(shutdownCtx)
}
