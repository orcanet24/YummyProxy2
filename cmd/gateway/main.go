package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"yummygateway/internal/config"
	"yummygateway/internal/gateway"
	"yummygateway/internal/store"
)

func main() {
	cfg := config.Load()
	setupLogger(cfg)

	slog.Info("starting yummy-gateway",
		"listen", cfg.ListenAddr,
		"db", cfg.DBPath,
		"admin_api", cfg.AdminToken != "",
		"public_base_url", cfg.PublicBaseURL,
	)
	if cfg.AdminToken == "" {
		slog.Warn("GATEWAY_ADMIN_TOKEN is not set: the /admin API is disabled")
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		slog.Error("could not open database", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	srv := gateway.NewServer(cfg, st)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Webhook delivery worker.
	go srv.Worker().Run(ctx)

	// Idle-cleanup for the rate limiter buckets.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Limiter().Cleanup(10 * time.Minute)
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "err", err)
		}
	}
	slog.Info("stopped")
}

func setupLogger(cfg config.Config) {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.LogJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}
