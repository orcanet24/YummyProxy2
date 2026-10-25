package gateway

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"yummygateway/internal/config"
	"yummygateway/internal/store"
)

// Server wires the store, auth cache, proxy, webhook receiver and admin API
// into a single http.Handler.
type Server struct {
	cfg      config.Config
	store    store.Store
	cache    *AuthCache
	limiter  *Limiter
	proxy    *Proxy
	webhooks *WebhookReceiver
	admin    *Admin
	worker   *Worker
}

func NewServer(cfg config.Config, st store.Store) *Server {
	cache := NewAuthCache(st, cfg.AuthCacheTTL)
	limiter := NewLimiter()
	proxy := NewProxy(st, cfg.UpstreamTimeout, cfg.MaxBodyBytes)
	worker := NewWorker(st, cfg.DeliverTimeout, cfg.WorkerInterval, cfg.WorkerBatch)
	webhooks := NewWebhookReceiver(st, cfg.WorkerInterval, worker.Poke)
	admin := NewAdmin(st, cfg, cache, worker.Poke)

	return &Server{
		cfg:      cfg,
		store:    st,
		cache:    cache,
		limiter:  limiter,
		proxy:    proxy,
		webhooks: webhooks,
		admin:    admin,
		worker:   worker,
	}
}

// Worker returns the webhook delivery worker (run it in its own goroutine).
func (s *Server) Worker() *Worker { return s.worker }

// Limiter exposes the per-tenant rate limiter (for periodic cleanup).
func (s *Server) Limiter() *Limiter { return s.limiter }

// Handler builds the full route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// --- health ------------------------------------------------------------
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.healthz)

	// --- Yummy webhooks (public: verified per-tenant with HMAC) ------------
	mux.HandleFunc("POST /webhooks/y/{token}", s.webhooks.Receive)

	// --- tenant-facing API (X-Gateway-Key) ---------------------------------
	auth := func(perm string, h http.HandlerFunc) http.HandlerFunc {
		return s.cache.keyAuth(s.limiter, perm, h)
	}

	mux.HandleFunc("POST /v1/stock/sync", auth("stock:write", s.proxy.StockSync))
	mux.HandleFunc("GET /v1/stock", auth("stock:read", s.proxy.StockList))
	mux.HandleFunc("PATCH /v1/sku", auth("price:write", s.proxy.PriceUpdate))
	mux.HandleFunc("GET /v1/orders", auth("orders:read", s.proxy.Orders))
	mux.HandleFunc("GET /v1/chat/messages", auth("chat:read", s.proxy.ChatMessages))
	mux.HandleFunc("GET /v1/chat/{chatId}/messages", auth("chat:read", s.proxy.ChatHistory))
	mux.HandleFunc("POST /v1/chat/{chatId}/messages", auth("chat:write", s.proxy.ChatReply))

	// Generic passthrough: /v1/yummy/<seller-api path>
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		mux.HandleFunc(m+" /v1/yummy/{path...}", s.passthroughWithPerm())
	}

	// --- admin API ---------------------------------------------------------
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("POST /admin/tenants", s.admin.CreateTenant)
	adminMux.HandleFunc("GET /admin/tenants", s.admin.ListTenants)
	adminMux.HandleFunc("GET /admin/tenants/{id}", s.admin.GetTenant)
	adminMux.HandleFunc("PATCH /admin/tenants/{id}", s.admin.UpdateTenant)
	adminMux.HandleFunc("DELETE /admin/tenants/{id}", s.admin.DeleteTenant)
	adminMux.HandleFunc("POST /admin/tenants/{id}/keys", s.admin.CreateKey)
	adminMux.HandleFunc("GET /admin/tenants/{id}/keys", s.admin.ListKeys)
	adminMux.HandleFunc("DELETE /admin/keys/{id}", s.admin.RevokeKey)
	adminMux.HandleFunc("GET /admin/events", s.admin.ListEvents)
	adminMux.HandleFunc("GET /admin/events/{id}", s.admin.GetEvent)
	adminMux.HandleFunc("POST /admin/events/{id}/retry", s.admin.RetryEvent)
	mux.Handle("/admin/", s.admin.Middleware(adminMux))

	// --- root --------------------------------------------------------------
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown path")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "yummy-gateway",
			"endpoints": []string{"/v1/stock", "/v1/stock/sync", "/v1/sku", "/v1/orders",
				"/v1/chat/messages", "/v1/yummy/*", "/webhooks/y/{token}", "/admin/*", "/healthz"},
		})
	})

	return withRecovery(withLogging(mux))
}

// passthroughWithPerm resolves the tenant first (to infer the permission of
// an arbitrary path), then delegates to the normal auth flow.
func (s *Server) passthroughWithPerm() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// keyAuth with "" accepts any key; we still need the tenant resolved,
		// so authenticate manually and then check the inferred permission.
		raw := extractKey(r)
		if raw == "" || !IsGatewayKeyShape(raw) {
			writeError(w, http.StatusUnauthorized, "INVALID_API_KEY", "missing or malformed gateway key")
			return
		}
		t, k, err := s.cache.Resolve(r.Context(), raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "INVALID_API_KEY", "unknown or revoked gateway key")
			return
		}
		perm := inferPermission(r.Method, "/"+r.PathValue("path"))
		if !store.HasPermission(k.Permissions, perm) {
			writeError(w, http.StatusForbidden, "MISSING_PERMISSION",
				"this key does not have the permission "+perm)
			return
		}
		if !s.limiter.Allow(t.ID, t.RatePerSecond, t.RateBurst) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded for this tenant")
			return
		}
		ctx := withTenant(r.Context(), t, k)
		s.proxy.Passthrough(w, r.WithContext(ctx))
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "degraded",
			"db":     err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "db": "ok"})
}

// ---- middleware ------------------------------------------------------------

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		// Webhook/event endpoints can be noisy; log everything at debug and
		// non-2xx at warn.
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		}
		if sw.status >= 500 {
			slog.Error("request", attrs...)
		} else if sw.status >= 400 {
			slog.Warn("request", attrs...)
		} else {
			slog.Info("request", attrs...)
		}
	})
}

func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered",
					"panic", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "INTERNAL", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
