package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Signature formats supported by the gateway.
//
// NOTE: the HMAC section of the Yummy docs was missing from the exported
// .txt, so the exact header name/format is configurable per tenant:
//
//   - "hex"    : header value is the raw hex HMAC-SHA256 of the body
//   - "sha256" : header value is "sha256=<hex>"
//   - "t"      : header value is "t=<unix>,v1=<hex>" (Stripe style),
//     HMAC over "<t>.<body>"
//   - "off"    : verification disabled (only allowed when no secret is set)
const (
	SigFormatHex    = "hex"
	SigFormatSHA256 = "sha256"
	SigFormatT      = "t"
	SigFormatOff    = "off"
)

// hmacHex computes HMAC-SHA256(secret, data) as lowercase hex.
func hmacHex(secret string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyIncoming checks the signature Yummy (or any upstream) sent us.
func VerifyIncoming(signature, secret, format string, body []byte) bool {
	if secret == "" || format == SigFormatOff {
		return true // verification disabled for this tenant
	}
	if signature == "" {
		return false
	}
	expected := hmacHex(secret, body)

	switch format {
	case SigFormatSHA256:
		v := strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
		return subtle.ConstantTimeCompare([]byte(strings.ToLower(v)), []byte(expected)) == 1
	case SigFormatT:
		parts := strings.Split(signature, ",")
		var ts, sig string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "t=") {
				ts = strings.TrimPrefix(p, "t=")
			}
			if strings.HasPrefix(p, "v1=") {
				sig = strings.TrimPrefix(p, "v1=")
			}
		}
		if ts == "" || sig == "" {
			return false
		}
		if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
			return false
		}
		return hmacHex(secret, []byte(ts+"."+string(body))) == strings.ToLower(sig)
	default: // SigFormatHex
		return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(signature)), []byte(expected)) == 1
	}
}

// SignDelivery builds the "t=<unix>,v1=<hex>" header we attach when
// forwarding webhooks to a tenant's callback URL.
func SignDelivery(secret string, ts time.Time, body []byte) string {
	t := strconv.FormatInt(ts.Unix(), 10)
	return fmt.Sprintf("t=%s,v1=%s", t, hmacHex(secret, []byte(t+"."+string(body))))
}

// VerifyDelivery checks a signature produced by SignDelivery (used in tests
// and available to tenants that re-sign before forwarding downstream).
func VerifyDelivery(signature, secret string, ts time.Time, body []byte) bool {
	return subtle.ConstantTimeCompare(
		[]byte(strings.TrimSpace(signature)),
		[]byte(SignDelivery(secret, ts, body)),
	) == 1
}

// HashKey returns the SHA-256 hex digest used to store gateway API keys.
func HashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
