package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"yummygateway/internal/config"
	"yummygateway/internal/store"
)

const testAdminToken = "adm-test-token"

func testConfig() config.Config {
	return config.Config{
		AdminToken:      testAdminToken,
		PublicBaseURL:   "http://gateway.test",
		UpstreamTimeout: 5 * time.Second,
		DeliverTimeout:  5 * time.Second,
		WorkerInterval:  10 * time.Millisecond,
		WorkerBatch:     10,
		MaxBodyBytes:    4 << 20,
		AuthCacheTTL:    time.Minute,
		DefaultRPS:      10000,
		DefaultBurst:    10000,
	}
}

func newTestApp(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	cfg := testConfig()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := NewServer(cfg, st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		st.Close()
	})
	return ts, srv
}

// call performs a request and returns the response plus its body.
func call(t *testing.T, method, url string, hdr map[string]string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

type tenantResp struct {
	ID           string `json:"id"`
	WebhookToken string `json:"webhook_token"`
	WebhookURL   string `json:"webhook_url"`
	CallbackURL  string `json:"callback_url"`
}

func adminHdr() map[string]string {
	return map[string]string{"X-Admin-Token": testAdminToken}
}

// hookURL points at the running test server instead of GATEWAY_PUBLIC_BASE_URL.
func hookURL(ts *httptest.Server, tn tenantResp) string {
	return ts.URL + "/webhooks/y/" + tn.WebhookToken
}

func createTenant(t *testing.T, base string, body map[string]any) tenantResp {
	t.Helper()
	resp, raw := call(t, http.MethodPost, base+"/admin/tenants", adminHdr(), body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create tenant: %d %s", resp.StatusCode, raw)
	}
	var out tenantResp
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode tenant: %v", err)
	}
	return out
}

func createKey(t *testing.T, base, tenantID string, perms []string) string {
	t.Helper()
	resp, raw := call(t, http.MethodPost, base+"/admin/tenants/"+tenantID+"/keys", adminHdr(),
		map[string]any{"label": "test", "permissions": perms})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key: %d %s", resp.StatusCode, raw)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Key == "" {
		t.Fatalf("decode key: %v %s", err, raw)
	}
	return out.Key
}

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------

func TestAdminRequiresToken(t *testing.T) {
	ts, _ := newTestApp(t)

	resp, _ := call(t, http.MethodGet, ts.URL+"/admin/tenants", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: expected 401, got %d", resp.StatusCode)
	}
	resp, _ = call(t, http.MethodGet, ts.URL+"/admin/tenants",
		map[string]string{"X-Admin-Token": "wrong"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: expected 401, got %d", resp.StatusCode)
	}
	resp, _ = call(t, http.MethodGet, ts.URL+"/admin/tenants", adminHdr(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token: expected 200, got %d", resp.StatusCode)
	}
}

func TestTenantLifecycle(t *testing.T) {
	ts, _ := newTestApp(t)

	tn := createTenant(t, ts.URL, map[string]any{
		"name":           "CRM Principal",
		"callback_url":   "http://localhost:1/hook",
		"yummy_base_url": "http://localhost:2",
		"yummy_api_key":  "mk_tst_secret",
		"webhook_secret": "wh-secret",
	})
	if tn.ID == "" || tn.WebhookURL == "" {
		t.Fatalf("tenant response incomplete: %+v", tn)
	}
	if !strings.HasPrefix(tn.WebhookURL, "http://gateway.test/webhooks/y/") {
		t.Fatalf("unexpected webhook url: %s", tn.WebhookURL)
	}

	// Duplicated slug must be a 409.
	resp, raw := call(t, http.MethodPost, ts.URL+"/admin/tenants", adminHdr(), map[string]any{
		"name": "CRM Principal",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate name/slug, got %d %s", resp.StatusCode, raw)
	}

	// PATCH updates without wiping other fields.
	resp, raw = call(t, http.MethodPatch, ts.URL+"/admin/tenants/"+tn.ID, adminHdr(),
		map[string]any{"callback_url": "http://localhost:3/hook2"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d %s", resp.StatusCode, raw)
	}
	var patched tenantResp
	_ = json.Unmarshal(raw, &patched)
	if patched.CallbackURL != "http://localhost:3/hook2" {
		t.Fatalf("callback not updated: %+v", patched)
	}

	// Secrets never leak in responses.
	if strings.Contains(string(raw), "mk_tst_secret") || strings.Contains(string(raw), "wh-secret") {
		t.Fatalf("secrets leaked in admin response: %s", raw)
	}

	// Key issued exactly once.
	key := createKey(t, ts.URL, tn.ID, []string{"*"})
	if !strings.HasPrefix(key, "gw_live_") {
		t.Fatalf("unexpected key format: %s", key)
	}
	resp, raw = call(t, http.MethodGet, ts.URL+"/admin/tenants/"+tn.ID, adminHdr(), nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(raw), key) {
		t.Fatalf("plaintext key must not be readable later: %d %s", resp.StatusCode, raw)
	}
}

// ---------------------------------------------------------------------------
// Tenant-facing proxy API
// ---------------------------------------------------------------------------

func TestProxyInjectsCredentialAndEnforcesPermissions(t *testing.T) {
	var gotKey, gotPath, gotQuery, gotBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("x-api-key"))
		gotPath.Store(r.URL.Path)
		gotQuery.Store(r.URL.RawQuery)
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[],"pagination":{"currentPage":1}}`))
	}))
	defer upstream.Close()

	ts, _ := newTestApp(t)
	tn := createTenant(t, ts.URL, map[string]any{
		"name":           "CRM",
		"yummy_base_url": upstream.URL,
		"yummy_api_key":  "mk_tst_upstream_key",
	})
	fullKey := createKey(t, ts.URL, tn.ID, []string{"*"})
	readonlyKey := createKey(t, ts.URL, tn.ID, []string{"stock:read"})

	// 1. Missing key -> 401.
	resp, _ := call(t, http.MethodGet, ts.URL+"/v1/stock?sku=ABC", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing key: expected 401, got %d", resp.StatusCode)
	}

	// 2. Garbage key -> 401.
	resp, _ = call(t, http.MethodGet, ts.URL+"/v1/stock",
		map[string]string{"X-Gateway-Key": "gw_live_zzzzzzzzzzzzzzzz"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad key: expected 401, got %d", resp.StatusCode)
	}

	// 3. Allowed read: credential injected, query preserved, body relayed.
	resp, raw := call(t, http.MethodGet, ts.URL+"/v1/stock?sku=CAMISA-AZUL-M&limit=10",
		map[string]string{"X-Gateway-Key": fullKey}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stock read: expected 200, got %d %s", resp.StatusCode, raw)
	}
	if gotKey.Load() != "mk_tst_upstream_key" {
		t.Fatalf("upstream did not receive the tenant API key: %v", gotKey.Load())
	}
	if gotPath.Load() != "/seller-api/v1/stock" {
		t.Fatalf("wrong upstream path: %v", gotPath.Load())
	}
	if gotQuery.Load() != "sku=CAMISA-AZUL-M&limit=10" {
		t.Fatalf("query not forwarded: %v", gotQuery.Load())
	}
	if resp.Header.Get("X-Gateway-Upstream-Status") != "200" {
		t.Fatalf("missing upstream status header")
	}

	// 4. Write with a read-only key -> 403 locally (never reaches Yummy).
	resp, _ = call(t, http.MethodPost, ts.URL+"/v1/stock/sync",
		map[string]string{"X-Gateway-Key": readonlyKey},
		map[string]any{"items": []any{map[string]any{"sku": "A", "stock": 1, "operation": "set"}}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only key: expected 403, got %d", resp.StatusCode)
	}

	// 5. Same write with the full key reaches upstream with the body intact.
	resp, raw = call(t, http.MethodPost, ts.URL+"/v1/stock/sync",
		map[string]string{"X-Gateway-Key": fullKey},
		map[string]any{"items": []any{map[string]any{"sku": "A", "stock": 1, "operation": "set"}}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stock sync: expected 200, got %d %s", resp.StatusCode, raw)
	}
	if gotPath.Load() != "/seller-api/v1/stock/sync" {
		t.Fatalf("wrong sync path: %v", gotPath.Load())
	}
	if !strings.Contains(gotBody.Load().(string), `"operation":"set"`) {
		t.Fatalf("body not forwarded: %v", gotBody.Load())
	}

	// 6. Generic passthrough keeps the same auth rules.
	resp, _ = call(t, http.MethodGet, ts.URL+"/v1/yummy/orders?startDate=2026-07-01",
		map[string]string{"X-Gateway-Key": fullKey}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passthrough orders: got %d", resp.StatusCode)
	}
	if gotPath.Load() != "/seller-api/v1/orders" {
		t.Fatalf("wrong passthrough path: %v", gotPath.Load())
	}
	resp, _ = call(t, http.MethodGet, ts.URL+"/v1/yummy/orders",
		map[string]string{"X-Gateway-Key": readonlyKey}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only key on orders: expected 403, got %d", resp.StatusCode)
	}

	// 7. Revoking a key stops it immediately.
	_, raw = call(t, http.MethodGet, ts.URL+"/admin/tenants/"+tn.ID, adminHdr(), nil)
	var detail struct {
		Keys []struct {
			ID          string   `json:"id"`
			Permissions []string `json:"permissions"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode keys: %v %s", err, raw)
	}
	var readonlyID string
	for _, k := range detail.Keys {
		if len(k.Permissions) == 1 && k.Permissions[0] == "stock:read" {
			readonlyID = k.ID
		}
	}
	if readonlyID == "" {
		t.Fatalf("readonly key id not found: %s", raw)
	}
	resp, raw = call(t, http.MethodDelete, ts.URL+"/admin/keys/"+readonlyID, adminHdr(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d %s", resp.StatusCode, raw)
	}
	resp, _ = call(t, http.MethodGet, ts.URL+"/v1/stock",
		map[string]string{"X-Gateway-Key": readonlyKey}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked key: expected 401, got %d", resp.StatusCode)
	}
	// The full key still works.
	resp, _ = call(t, http.MethodGet, ts.URL+"/v1/stock",
		map[string]string{"X-Gateway-Key": fullKey}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("full key should still work, got %d", resp.StatusCode)
	}
}

func TestUpstreamDownReturns502(t *testing.T) {
	// A base URL that refuses connections.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	ts, _ := newTestApp(t)
	tn := createTenant(t, ts.URL, map[string]any{
		"name":           "CRM",
		"yummy_base_url": deadURL,
		"yummy_api_key":  "mk_tst_x",
	})
	key := createKey(t, ts.URL, tn.ID, []string{"*"})

	resp, _ := call(t, http.MethodGet, ts.URL+"/v1/stock",
		map[string]string{"X-Gateway-Key": key}, nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 when upstream is down, got %d", resp.StatusCode)
	}
}

func TestTenantWithoutUpstreamReturns503(t *testing.T) {
	ts, _ := newTestApp(t)
	tn := createTenant(t, ts.URL, map[string]any{"name": "Sin Upstream"})
	key := createKey(t, ts.URL, tn.ID, []string{"*"})

	resp, raw := call(t, http.MethodGet, ts.URL+"/v1/stock",
		map[string]string{"X-Gateway-Key": key}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d %s", resp.StatusCode, raw)
	}
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

func TestWebhookReceiveVerifyAndDeliver(t *testing.T) {
	var delivered atomic.Value
	var deliveredSig atomic.Value
	var attempt atomic.Int32
	ok := atomic.Bool{}
	ok.Store(false)

	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		delivered.Store(string(b))
		deliveredSig.Store(r.Header.Get("X-Gateway-Signature"))
		attempt.Add(1)
		if !ok.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer callback.Close()

	ts, srv := newTestApp(t)
	tn := createTenant(t, ts.URL, map[string]any{
		"name":            "CRM",
		"callback_url":    callback.URL,
		"callback_secret": "cb-secret",
		"webhook_secret":  "wh-secret",
	})

	payload := `{"event":"order.items.sold","orderId":"667a","items":[]}`
	sig := hmacHex("wh-secret", []byte(payload))

	// 1. Wrong signature -> 403, nothing stored.
	resp, _ := call(t, http.MethodPost, hookURL(ts, tn),
		map[string]string{"X-Yummy-Signature": "00" + sig[2:], "Content-Type": "application/json"},
		json.RawMessage(payload))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad signature: expected 403, got %d", resp.StatusCode)
	}

	// 2. Valid signature -> 200 and persisted.
	resp, raw := call(t, http.MethodPost, hookURL(ts, tn),
		map[string]string{"X-Yummy-Signature": sig, "Content-Type": "application/json"},
		json.RawMessage(payload))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid webhook: expected 200, got %d %s", resp.StatusCode, raw)
	}
	var ack struct {
		Received bool   `json:"received"`
		EventID  string `json:"eventId"`
		Type     string `json:"type"`
	}
	if err := json.Unmarshal(raw, &ack); err != nil || !ack.Received {
		t.Fatalf("bad ack: %v %s", err, raw)
	}
	if ack.Type != "order.items.sold" {
		t.Fatalf("event type not detected: %q", ack.Type)
	}

	// 3. First delivery attempt fails (callback returns 500) -> retry scheduled.
	srv.Worker().tick(context.Background())
	if attempt.Load() != 1 {
		t.Fatalf("expected 1 delivery attempt, got %d", attempt.Load())
	}
	ev, err := srv.store.GetEvent(context.Background(), ack.EventID)
	if err != nil {
		t.Fatalf("event not stored: %v", err)
	}
	if ev.Status != store.EventPending || ev.Attempts != 1 || ev.LastError == "" {
		t.Fatalf("expected failed attempt to be scheduled for retry: %+v", ev)
	}

	// 4. Manual retry (what the admin endpoint does) makes it due again.
	ok.Store(true)
	if err := srv.store.ResetEvent(context.Background(), ack.EventID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	srv.Worker().tick(context.Background())
	got := delivered.Load().(string)
	if !strings.Contains(got, "667a") {
		t.Fatalf("payload not forwarded: %s", got)
	}
	sigHdr := deliveredSig.Load().(string)
	if sigHdr == "" {
		t.Fatalf("delivery signature header missing")
	}
	ts2 := time.Unix(mustParseInt(t, strings.TrimPrefix(sigHdr, "t=")), 0)
	if !VerifyDelivery(sigHdr, "cb-secret", ts2, []byte(got)) {
		t.Fatalf("tenant-side verification of our signature failed: %s", sigHdr)
	}

	ev, _ = srv.store.GetEvent(context.Background(), ack.EventID)
	if ev.Status != store.EventDelivered {
		t.Fatalf("expected delivered, got %+v", ev)
	}

	// 5. Unknown webhook token -> 404.
	resp, _ = call(t, http.MethodPost, ts.URL+"/webhooks/y/not-a-real-token", nil, `{}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token: expected 404, got %d", resp.StatusCode)
	}
}

func TestWebhookAcceptedWithoutSecret(t *testing.T) {
	ts, srv := newTestApp(t)
	tn := createTenant(t, ts.URL, map[string]any{"name": "Sin Secreto"})

	resp, raw := call(t, http.MethodPost, hookURL(ts, tn), nil,
		map[string]any{"event": "chat.message.received"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when no secret configured, got %d %s", resp.StatusCode, raw)
	}
	if srv.store == nil {
		t.Fatal("store not wired")
	}
}

func TestHealthz(t *testing.T) {
	ts, _ := newTestApp(t)
	resp, raw := call(t, http.MethodGet, ts.URL+"/healthz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d %s", resp.StatusCode, raw)
	}
}

// mustParseInt extracts the seconds value from a "t=...,v1=..." signature.
func mustParseInt(t *testing.T, s string) int64 {
	t.Helper()
	comma := strings.Index(s, ",")
	if comma < 0 {
		t.Fatalf("malformed signature: %s", s)
	}
	var n int64
	for _, r := range s[:comma] {
		if r < '0' || r > '9' {
			t.Fatalf("not a number: %s", s)
		}
		n = n*10 + int64(r-'0')
	}
	return n
}
