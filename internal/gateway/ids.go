package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// KeyPrefix identifies a gateway-issued key: gw_live_<32 hex>.
	keyPrefix = "gw_live_"
	// tokenBytes is the size of opaque tokens (webhook path token, secrets).
	tokenBytes = 16
)

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewGatewayKey mints a fresh gateway API key plus its hash and display prefix.
func NewGatewayKey() (raw, hash, prefix string, err error) {
	secret, err := randomHex(16)
	if err != nil {
		return "", "", "", err
	}
	raw = keyPrefix + secret
	return raw, HashKey(raw), raw[:len(keyPrefix)+4], nil
}

// IsGatewayKeyShape does a cheap plausibility check before hitting the DB.
func IsGatewayKeyShape(raw string) bool {
	return strings.HasPrefix(raw, keyPrefix) && len(raw) >= len(keyPrefix)+16
}

func newWebhookToken() (string, error) {
	return randomHex(tokenBytes)
}

func newSecret() (string, error) {
	return randomHex(tokenBytes)
}

// newID builds prefixed identifiers: tnt_, key_, evt_.
func newID(prefix string) (string, error) {
	return randomID(prefix, 8)
}
