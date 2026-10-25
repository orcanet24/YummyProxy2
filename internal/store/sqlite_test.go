package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleTenant(id string) *Tenant {
	now := time.Now().UTC()
	return &Tenant{
		ID:               id,
		WebhookToken:     "tok_" + id,
		Name:             "Test " + id,
		Slug:             "test-" + id,
		Active:           true,
		CallbackURL:      "http://localhost:9999/hook",
		CallbackSecret:   "cb-secret",
		YummyBaseURL:     "http://localhost:8888",
		YummyAPIKey:      "mk_tst_abc",
		WebhookSecret:    "wh-secret",
		WebhookSigHeader: "x-yummy-signature",
		WebhookSigFormat: SigFormatTest,
		RatePerSecond:    60,
		RateBurst:        120,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// SigFormatTest keeps this test independent of the gateway package.
const SigFormatTest = "hex"

func TestTenantCRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	tn := sampleTenant("tnt_1")
	if err := s.CreateTenant(ctx, tn); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.CreateTenant(ctx, tn); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	got, err := s.GetTenant(ctx, "tnt_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.YummyAPIKey != "mk_tst_abc" || got.YummyBaseURL != "http://localhost:8888" {
		t.Fatalf("unexpected tenant: %+v", got)
	}

	byTok, err := s.GetTenantByWebhookToken(ctx, "tok_tnt_1")
	if err != nil || byTok.ID != "tnt_1" {
		t.Fatalf("lookup by webhook token: %v %+v", err, byTok)
	}

	got.Name = "Renamed"
	got.Active = false
	if err := s.UpdateTenant(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := s.GetTenant(ctx, "tnt_1")
	if again.Name != "Renamed" || again.Active {
		t.Fatalf("update not applied: %+v", again)
	}

	list, err := s.ListTenants(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}

	if err := s.DeleteTenant(ctx, "tnt_1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetTenant(ctx, "tnt_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestKeyResolutionAndRevocation(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.CreateTenant(ctx, sampleTenant("tnt_1")); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	k := &ProxyKey{
		ID:          "key_1",
		TenantID:    "tnt_1",
		Label:       "crm",
		Permissions: []string{"stock:read"},
		KeyHash:     "hash-abc",
		Prefix:      "gw_live_ab",
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.CreateProxyKey(ctx, k); err != nil {
		t.Fatalf("create key: %v", err)
	}

	tn, resolved, err := s.ResolveKey(ctx, "hash-abc")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if tn.ID != "tnt_1" || resolved.ID != "key_1" {
		t.Fatalf("wrong resolution: %+v %+v", tn, resolved)
	}
	if len(resolved.Permissions) != 1 || resolved.Permissions[0] != "stock:read" {
		t.Fatalf("permissions lost: %+v", resolved.Permissions)
	}

	if err := s.RevokeProxyKey(ctx, "key_1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := s.ResolveKey(ctx, "hash-abc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found after revoke, got %v", err)
	}

	// Inactive tenant keys must not resolve.
	if err := s.RevokeProxyKey(ctx, "key_1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestInactiveTenantBlocksKey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	tn := sampleTenant("tnt_1")
	tn.Active = false
	if err := s.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateProxyKey(ctx, &ProxyKey{
		ID: "key_1", TenantID: "tnt_1", Permissions: []string{"*"},
		KeyHash: "h", Prefix: "gw_live_ab", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ResolveKey(ctx, "h"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found for inactive tenant, got %v", err)
	}
}

func TestWebhookEventClaimCycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.CreateTenant(ctx, sampleTenant("tnt_1")); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	for _, id := range []string{"evt_a", "evt_b"} {
		if err := s.SaveWebhookEvent(ctx, &WebhookEvent{
			ID: id, TenantID: "tnt_1", EventType: "order.items.sold",
			Payload:    []byte(`{"event":"order.items.sold"}`),
			ReceivedAt: now, Status: EventPending, NextAttemptAt: now.Add(-time.Second),
		}); err != nil {
			t.Fatalf("save %s: %v", id, err)
		}
	}
	// One event in the future must not be claimed yet.
	if err := s.SaveWebhookEvent(ctx, &WebhookEvent{
		ID: "evt_future", TenantID: "tnt_1", Payload: []byte(`{}`),
		ReceivedAt: now, Status: EventPending, NextAttemptAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	claimed, err := s.ClaimDueEvents(ctx, now, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 2 {
		t.Fatalf("expected 2 claimed, got %d", len(claimed))
	}
	for _, ev := range claimed {
		if ev.Status != EventDelivering || ev.Attempts != 1 {
			t.Fatalf("claim not applied: %+v", ev)
		}
	}

	// A second claim while delivering must return nothing (no double send).
	again, err := s.ClaimDueEvents(ctx, now, 10)
	if err != nil || len(again) != 0 {
		t.Fatalf("expected no re-claim, got %d err=%v", len(again), err)
	}

	if err := s.MarkEventDelivered(ctx, "evt_a", now); err != nil {
		t.Fatal(err)
	}
	delivered, _ := s.GetEvent(ctx, "evt_a")
	if delivered.Status != EventDelivered || delivered.DeliveredAt == nil {
		t.Fatalf("delivery not recorded: %+v", delivered)
	}

	if err := s.ScheduleEventRetry(ctx, "evt_b", now, "status 500", false); err != nil {
		t.Fatal(err)
	}
	retry, _ := s.GetEvent(ctx, "evt_b")
	if retry.Status != EventPending || retry.LastError == "" {
		t.Fatalf("retry not scheduled: %+v", retry)
	}

	// Crash recovery: delivering -> pending.
	if err := s.RecoverStaleDeliveries(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, _ := s.GetEvent(ctx, "evt_b")
	if recovered.Status != EventPending {
		t.Fatalf("expected pending, got %s", recovered.Status)
	}

	if err := s.ResetEvent(ctx, "evt_a"); err != nil {
		t.Fatal(err)
	}
	reset, _ := s.GetEvent(ctx, "evt_a")
	if reset.Status != EventPending || reset.Attempts != 0 {
		t.Fatalf("reset failed: %+v", reset)
	}

	// Purge only removes terminal (delivered/failed) events.
	if err := s.MarkEventDelivered(ctx, "evt_a", now); err != nil {
		t.Fatalf("re-deliver: %v", err)
	}
	n, err := s.PurgeDelivered(ctx, now.Add(time.Hour))
	if err != nil || n < 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := s.GetEvent(ctx, "evt_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected purged event to be gone, got %v", err)
	}
}

func TestPermissionHelper(t *testing.T) {
	cases := []struct {
		perms []string
		want  string
		ok    bool
	}{
		{[]string{"*"}, "stock:write", true},
		{[]string{"stock:read", "orders:read"}, "orders:read", true},
		{[]string{"stock:read"}, "stock:write", false},
		{[]string{}, "stock:read", false},
		{nil, "stock:read", false},
		{[]string{"stock:read"}, "", true}, // "" = no permission required
	}
	for _, c := range cases {
		if got := HasPermission(c.perms, c.want); got != c.ok {
			t.Errorf("HasPermission(%v, %q) = %v, want %v", c.perms, c.want, got, c.ok)
		}
	}
}
