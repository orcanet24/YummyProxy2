package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"yummygateway/internal/config"
	"yummygateway/internal/store"
)

// Admin exposes the operator API used to manage tenants, gateway keys,
// Yummy credentials and webhook events. Protected by GATEWAY_ADMIN_TOKEN.
type Admin struct {
	store store.Store
	cfg   config.Config
	cache *AuthCache
	// poke tells the delivery worker that a manual retry was requested.
	poke func()
}

func NewAdmin(st store.Store, cfg config.Config, cache *AuthCache, poke func()) *Admin {
	return &Admin{store: st, cfg: cfg, cache: cache, poke: poke}
}

// Middleware enforces the admin token (constant-time comparison).
func (a *Admin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.AdminToken == "" {
			writeError(w, http.StatusServiceUnavailable, "ADMIN_DISABLED",
				"GATEWAY_ADMIN_TOKEN is not set; the admin API is disabled")
			return
		}
		got := r.Header.Get("X-Admin-Token")
		if got == "" {
			if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
				got = v[7:]
			}
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.cfg.AdminToken)) != 1 {
			logKeyAuthFailure(r)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tenantView adds derived, non-persisted fields to the tenant JSON.
type tenantView struct {
	*store.Tenant
	YummyAPIKeySet   bool   `json:"yummy_api_key_set"`
	WebhookSecretSet bool   `json:"webhook_secret_set"`
	WebhookURL       string `json:"webhook_url"`
}

func (a *Admin) view(t *store.Tenant) tenantView {
	return tenantView{
		Tenant:           t,
		YummyAPIKeySet:   t.YummyAPIKey != "",
		WebhookSecretSet: t.WebhookSecret != "",
		WebhookURL:       a.webhookURL(t),
	}
}

func (a *Admin) webhookURL(t *store.Tenant) string {
	return strings.TrimRight(a.cfg.PublicBaseURL, "/") + "/webhooks/y/" + t.WebhookToken
}

// ---- tenants ---------------------------------------------------------------

type createTenantReq struct {
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	Active           *bool    `json:"active"`
	CallbackURL      string   `json:"callback_url"`
	CallbackSecret   string   `json:"callback_secret"`
	YummyBaseURL     string   `json:"yummy_base_url"`
	YummyAPIKey      string   `json:"yummy_api_key"`
	WebhookSecret    string   `json:"webhook_secret"`
	WebhookSigHeader string   `json:"webhook_signature_header"`
	WebhookSigFormat string   `json:"webhook_signature_format"`
	RatePerSecond    *float64 `json:"rate_per_second"`
	RateBurst        *int     `json:"rate_burst"`
}

func (a *Admin) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantReq
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION", "name is required")
		return
	}
	slug := req.Slug
	if slug == "" {
		slug = slugify(req.Name)
	}
	if req.CallbackURL != "" && !validURL(req.CallbackURL) {
		writeError(w, http.StatusBadRequest, "VALIDATION", "callback_url must be http(s)")
		return
	}
	if req.WebhookSigFormat != "" && !validSigFormat(req.WebhookSigFormat) {
		writeError(w, http.StatusBadRequest, "VALIDATION",
			"webhook_signature_format must be one of hex, sha256, t, off")
		return
	}

	token, err := newWebhookToken()
	if err != nil {
		respondStoreError(w, err)
		return
	}
	secret := req.CallbackSecret
	if secret == "" {
		if secret, err = newSecret(); err != nil {
			respondStoreError(w, err)
			return
		}
	}
	id, err := newID("tnt")
	if err != nil {
		respondStoreError(w, err)
		return
	}

	now := nowUTC()
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	t := &store.Tenant{
		ID:               id,
		WebhookToken:     token,
		Name:             strings.TrimSpace(req.Name),
		Slug:             slug,
		Active:           active,
		CallbackURL:      strings.TrimSpace(req.CallbackURL),
		CallbackSecret:   secret,
		YummyBaseURL:     strings.TrimRight(strings.TrimSpace(req.YummyBaseURL), "/"),
		YummyAPIKey:      strings.TrimSpace(req.YummyAPIKey),
		WebhookSecret:    strings.TrimSpace(req.WebhookSecret),
		WebhookSigHeader: defaultStr(req.WebhookSigHeader, "x-yummy-signature"),
		WebhookSigFormat: defaultStr(req.WebhookSigFormat, SigFormatHex),
		RatePerSecond:    a.cfg.DefaultRPS,
		RateBurst:        a.cfg.DefaultBurst,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if req.RatePerSecond != nil {
		t.RatePerSecond = *req.RatePerSecond
	}
	if req.RateBurst != nil {
		t.RateBurst = *req.RateBurst
	}

	if err := a.store.CreateTenant(r.Context(), t); err != nil {
		respondStoreError(w, err)
		return
	}
	a.cache.Invalidate()
	writeJSON(w, http.StatusCreated, a.view(t))
}

func (a *Admin) ListTenants(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListTenants(r.Context())
	if err != nil {
		respondStoreError(w, err)
		return
	}
	out := make([]tenantView, 0, len(list))
	for _, t := range list {
		out = append(out, a.view(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out, "count": len(out)})
}

func (a *Admin) GetTenant(w http.ResponseWriter, r *http.Request) {
	t, err := a.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	keys, err := a.store.ListProxyKeys(r.Context(), t.ID)
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": a.view(t), "keys": keys})
}

type updateTenantReq struct {
	Name             *string  `json:"name"`
	Slug             *string  `json:"slug"`
	Active           *bool    `json:"active"`
	CallbackURL      *string  `json:"callback_url"`
	CallbackSecret   *string  `json:"callback_secret"`
	YummyBaseURL     *string  `json:"yummy_base_url"`
	YummyAPIKey      *string  `json:"yummy_api_key"`
	WebhookSecret    *string  `json:"webhook_secret"`
	WebhookSigHeader *string  `json:"webhook_signature_header"`
	WebhookSigFormat *string  `json:"webhook_signature_format"`
	RatePerSecond    *float64 `json:"rate_per_second"`
	RateBurst        *int     `json:"rate_burst"`
}

func (a *Admin) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	t, err := a.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	var req updateTenantReq
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		t.Name = strings.TrimSpace(*req.Name)
	}
	if req.Slug != nil && strings.TrimSpace(*req.Slug) != "" {
		t.Slug = strings.TrimSpace(*req.Slug)
	}
	if req.Active != nil {
		t.Active = *req.Active
	}
	if req.CallbackURL != nil {
		if *req.CallbackURL != "" && !validURL(*req.CallbackURL) {
			writeError(w, http.StatusBadRequest, "VALIDATION", "callback_url must be http(s)")
			return
		}
		t.CallbackURL = strings.TrimSpace(*req.CallbackURL)
	}
	if req.CallbackSecret != nil {
		t.CallbackSecret = *req.CallbackSecret
	}
	if req.YummyBaseURL != nil {
		t.YummyBaseURL = strings.TrimRight(strings.TrimSpace(*req.YummyBaseURL), "/")
	}
	if req.YummyAPIKey != nil {
		t.YummyAPIKey = strings.TrimSpace(*req.YummyAPIKey)
	}
	if req.WebhookSecret != nil {
		t.WebhookSecret = strings.TrimSpace(*req.WebhookSecret)
	}
	if req.WebhookSigHeader != nil && *req.WebhookSigHeader != "" {
		t.WebhookSigHeader = *req.WebhookSigHeader
	}
	if req.WebhookSigFormat != nil {
		if !validSigFormat(*req.WebhookSigFormat) {
			writeError(w, http.StatusBadRequest, "VALIDATION",
				"webhook_signature_format must be one of hex, sha256, t, off")
			return
		}
		t.WebhookSigFormat = *req.WebhookSigFormat
	}
	if req.RatePerSecond != nil {
		t.RatePerSecond = *req.RatePerSecond
	}
	if req.RateBurst != nil {
		t.RateBurst = *req.RateBurst
	}
	t.UpdatedAt = nowUTC()

	if err := a.store.UpdateTenant(r.Context(), t); err != nil {
		respondStoreError(w, err)
		return
	}
	a.cache.Invalidate()
	writeJSON(w, http.StatusOK, a.view(t))
}

func (a *Admin) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteTenant(r.Context(), r.PathValue("id")); err != nil {
		respondStoreError(w, err)
		return
	}
	a.cache.Invalidate()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- gateway keys ----------------------------------------------------------

type createKeyReq struct {
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
}

func (a *Admin) CreateKey(w http.ResponseWriter, r *http.Request) {
	t, err := a.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	var req createKeyReq
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	if req.Permissions == nil {
		req.Permissions = []string{"*"}
	}

	raw, hash, prefix, err := NewGatewayKey()
	if err != nil {
		respondStoreError(w, err)
		return
	}
	id, err := newID("key")
	if err != nil {
		respondStoreError(w, err)
		return
	}
	k := &store.ProxyKey{
		ID:          id,
		TenantID:    t.ID,
		Label:       req.Label,
		Permissions: req.Permissions,
		KeyHash:     hash,
		Prefix:      prefix,
		CreatedAt:   nowUTC(),
	}
	if err := a.store.CreateProxyKey(r.Context(), k); err != nil {
		respondStoreError(w, err)
		return
	}
	a.cache.Invalidate()

	// The plaintext key is returned exactly once.
	writeJSON(w, http.StatusCreated, map[string]any{
		"key":       raw,
		"proxy_key": k,
		"note":      "Store this key now: it is shown only once.",
	})
}

func (a *Admin) ListKeys(w http.ResponseWriter, r *http.Request) {
	t, err := a.store.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	keys, err := a.store.ListProxyKeys(r.Context(), t.ID)
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "count": len(keys)})
}

func (a *Admin) RevokeKey(w http.ResponseWriter, r *http.Request) {
	if err := a.store.RevokeProxyKey(r.Context(), r.PathValue("id")); err != nil {
		respondStoreError(w, err)
		return
	}
	a.cache.Invalidate()
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// ---- events ----------------------------------------------------------------

func (a *Admin) ListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{
		TenantID: q.Get("tenant_id"),
		Status:   q.Get("status"),
	}
	if v, err := parseInt(q.Get("limit")); err == nil {
		f.Limit = v
	}
	if v, err := parseInt(q.Get("offset")); err == nil {
		f.Offset = v
	}
	list, err := a.store.ListEvents(r.Context(), f)
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": list, "count": len(list)})
}

func (a *Admin) GetEvent(w http.ResponseWriter, r *http.Request) {
	ev, err := a.store.GetEvent(r.Context(), r.PathValue("id"))
	if err != nil {
		respondStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event":   ev,
		"payload": json.RawMessage(ev.Payload),
	})
}

func (a *Admin) RetryEvent(w http.ResponseWriter, r *http.Request) {
	if err := a.store.ResetEvent(r.Context(), r.PathValue("id")); err != nil {
		respondStoreError(w, err)
		return
	}
	if a.poke != nil {
		a.poke()
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": store.EventPending})
}

// ---- helpers ---------------------------------------------------------------

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func validSigFormat(f string) bool {
	switch f {
	case SigFormatHex, SigFormatSHA256, SigFormatT, SigFormatOff:
		return true
	}
	return false
}

func validURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "tenant"
	}
	return out
}

func parseInt(s string) (int, error) {
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(s)
}
