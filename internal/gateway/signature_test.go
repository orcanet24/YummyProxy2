package gateway

import (
	"testing"
	"time"
)

func TestVerifyIncomingFormats(t *testing.T) {
	body := []byte(`{"event":"order.items.sold","id":1}`)
	secret := "shared-secret"
	digest := hmacHex(secret, body)

	cases := []struct {
		name   string
		format string
		sig    string
		want   bool
	}{
		{"hex ok", SigFormatHex, digest, true},
		{"hex wrong", SigFormatHex, "deadbeef", false},
		{"hex empty", SigFormatHex, "", false},
		{"sha256 prefix ok", SigFormatSHA256, "sha256=" + digest, true},
		{"sha256 bare ok", SigFormatSHA256, digest, true},
		{"sha256 tampered", SigFormatSHA256, "sha256=00" + digest[2:], false},
	}
	for _, c := range cases {
		if got := VerifyIncoming(c.sig, secret, c.format, body); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}

	// Stripe-style t=...,v1=...
	ts := time.Unix(1700000000, 0)
	sig := SignDelivery(secret, ts, body)
	if !VerifyIncoming(sig, secret, SigFormatT, body) {
		t.Errorf("t-format signature should verify")
	}
	if VerifyIncoming(sig, secret, SigFormatT, []byte(`tampered`)) {
		t.Errorf("t-format signature must fail on modified body")
	}
	if VerifyIncoming("t=abc,v1=zzz", secret, SigFormatT, body) {
		t.Errorf("garbage t-format signature must fail")
	}

	// Verification disabled when no secret is configured.
	if !VerifyIncoming("", "", SigFormatHex, body) {
		t.Errorf("empty secret must skip verification")
	}
	if !VerifyIncoming("", secret, SigFormatOff, body) {
		t.Errorf("format off must skip verification")
	}
}

func TestSignDeliveryRoundTrip(t *testing.T) {
	body := []byte(`{"a":1}`)
	ts := time.Unix(1712345678, 0)
	sig := SignDelivery("s3cret", ts, body)
	if sig[:2] != "t=" {
		t.Fatalf("unexpected signature format: %s", sig)
	}
	if !VerifyDelivery(sig, "s3cret", ts, body) {
		t.Fatalf("round trip failed")
	}
	if VerifyDelivery(sig, "other-secret", ts, body) {
		t.Fatalf("wrong secret must not verify")
	}
}

func TestHashKeyIsStableAndCaseSensitive(t *testing.T) {
	a := HashKey("gw_live_abc")
	if a != HashKey("gw_live_abc") {
		t.Fatalf("hash must be stable")
	}
	if a == HashKey("gw_live_ABC") {
		t.Fatalf("hash must be case sensitive")
	}
	if !IsGatewayKeyShape("gw_live_0123456789abcdef") {
		t.Fatalf("shape check failed for valid key")
	}
	if IsGatewayKeyShape("sk_other_0123456789abcdef") {
		t.Fatalf("shape check accepted a foreign key")
	}
}

func TestInferPermission(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   string
	}{
		{"POST", "/seller-api/v1/stock/sync", "stock:write"},
		{"GET", "/seller-api/v1/stock", "stock:read"},
		{"PATCH", "/seller-api/v1/sku", "price:write"},
		{"GET", "/seller-api/v1/orders", "orders:read"},
		{"GET", "/seller-api/v1/chat/messages", "chat:read"},
		{"POST", "/seller-api/v1/chat/abc/messages", "chat:write"},
		{"GET", "/seller-api/v1/unknown", ""},
	}
	for _, c := range cases {
		if got := inferPermission(c.method, c.path); got != c.want {
			t.Errorf("inferPermission(%s, %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	// rps <= 0 disables limiting.
	for i := 0; i < 100; i++ {
		if !l.Allow("t1", 0, 1) {
			t.Fatalf("limiter should be disabled when rps=0")
		}
	}
	// burst of 3 allows exactly 3 immediate requests.
	for i := 0; i < 3; i++ {
		if !l.Allow("t2", 1, 3) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow("t2", 1, 3) {
		t.Fatalf("4th request should be rate limited")
	}
	// Independent tenants do not share buckets.
	if !l.Allow("t3", 1, 1) {
		t.Fatalf("other tenant should have its own bucket")
	}
}
