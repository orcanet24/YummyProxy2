package gateway

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"yummygateway/internal/store"
)

type ctxKeyKind int

const (
	ctxTenant ctxKeyKind = iota
	ctxKey
)

// AuthCache resolves gateway API keys from memory. Keys are hashed (SHA-256),
// looked up on a cache miss, and kept for a short TTL; any admin mutation
// resets the whole cache so changes land immediately.
type AuthCache struct {
	store store.Store
	ttl   time.Duration

	mu    sync.Mutex
	items map[string]authEntry
}

type authEntry struct {
	tenant  *store.Tenant
	key     *store.ProxyKey
	expires time.Time
}

func NewAuthCache(st store.Store, ttl time.Duration) *AuthCache {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &AuthCache{store: st, ttl: ttl, items: make(map[string]authEntry)}
}

// Resolve returns the active tenant and key for a raw gateway key.
func (a *AuthCache) Resolve(ctx context.Context, raw string) (*store.Tenant, *store.ProxyKey, error) {
	hash := HashKey(raw)

	a.mu.Lock()
	if e, ok := a.items[hash]; ok && time.Now().Before(e.expires) {
		a.mu.Unlock()
		return e.tenant, e.key, nil
	}
	a.mu.Unlock()

	t, k, err := a.store.ResolveKey(ctx, hash)
	if err != nil {
		return nil, nil, err
	}

	a.mu.Lock()
	a.items[hash] = authEntry{tenant: t, key: k, expires: time.Now().Add(a.ttl)}
	a.mu.Unlock()
	return t, k, nil
}

// Invalidate drops every cached credential (called after admin changes).
func (a *AuthCache) Invalidate() {
	a.mu.Lock()
	a.items = make(map[string]authEntry)
	a.mu.Unlock()
}

// tenantFrom returns the tenant stored by the auth middleware.
func tenantFrom(ctx context.Context) (*store.Tenant, *store.ProxyKey) {
	t, _ := ctx.Value(ctxTenant).(*store.Tenant)
	k, _ := ctx.Value(ctxKey).(*store.ProxyKey)
	return t, k
}

// withTenant attaches an already-resolved tenant/key pair to the context.
func withTenant(ctx context.Context, t *store.Tenant, k *store.ProxyKey) context.Context {
	ctx = context.WithValue(ctx, ctxTenant, t)
	return context.WithValue(ctx, ctxKey, k)
}

// extractKey accepts the key in X-Gateway-Key or "Authorization: Bearer ...".
func extractKey(r *http.Request) string {
	if v := r.Header.Get("X-Gateway-Key"); v != "" {
		return v
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && (auth[:7] == "Bearer " || auth[:7] == "bearer ") {
		return auth[7:]
	}
	return ""
}

// keyAuth authenticates a request, enforces `perm` (when non-empty) and the
// per-tenant rate limit, then hands the request to next.
func (a *AuthCache) keyAuth(l *Limiter, perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := extractKey(r)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "MISSING_API_KEY",
				"send the gateway key in X-Gateway-Key or Authorization: Bearer")
			return
		}
		if !IsGatewayKeyShape(raw) {
			writeError(w, http.StatusUnauthorized, "INVALID_API_KEY", "malformed gateway key")
			return
		}

		t, k, err := a.Resolve(r.Context(), raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "INVALID_API_KEY", "unknown or revoked gateway key")
			return
		}

		if !store.HasPermission(k.Permissions, perm) {
			writeError(w, http.StatusForbidden, "MISSING_PERMISSION",
				"this key does not have the permission "+perm)
			return
		}

		if !l.Allow(t.ID, t.RatePerSecond, t.RateBurst) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED",
				"rate limit exceeded for this tenant")
			return
		}

		ctx := context.WithValue(r.Context(), ctxTenant, t)
		ctx = context.WithValue(ctx, ctxKey, k)
		next(w, r.WithContext(ctx))
	}
}

// inferPermission maps an arbitrary seller-api path/method to the Yummy
// permission it needs, so the generic passthrough honours the same
// least-privilege model as the typed endpoints. "" means "unknown: let
// Yummy decide".
func inferPermission(method, path string) string {
	switch {
	case strings.Contains(path, "/stock/sync"):
		return "stock:write"
	case strings.Contains(path, "/stock"):
		if method == http.MethodGet {
			return "stock:read"
		}
		return "stock:write"
	case strings.Contains(path, "/sku"):
		return "price:write"
	case strings.Contains(path, "/orders"):
		return "orders:read"
	case strings.Contains(path, "/chat"):
		if method == http.MethodGet {
			return "chat:read"
		}
		return "chat:write"
	default:
		return ""
	}
}

// logKeyAuthFailure is a helper for the admin middleware.
func logKeyAuthFailure(r *http.Request) {
	slog.Warn("admin auth failed", "path", r.URL.Path, "remote", r.RemoteAddr)
}
