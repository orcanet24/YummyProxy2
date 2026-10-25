package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound / ErrConflict are surfaced as HTTP 404 / 409 by the handlers.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// Tenant is one consumer of the gateway (one of our CRM/ecommerce projects).
// It owns a gateway API key namespace, a Yummy credential and a webhook
// destination URL where Yummy events are forwarded to.
type Tenant struct {
	ID           string `json:"id"`
	WebhookToken string `json:"webhook_token"`
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	Active       bool   `json:"active"`

	// Where this tenant receives forwarded Yummy webhooks.
	CallbackURL    string `json:"callback_url"`
	CallbackSecret string `json:"-"` // HMAC key we sign deliveries with

	// Yummy upstream credential for this tenant.
	YummyBaseURL string `json:"yummy_base_url"`
	YummyAPIKey  string `json:"-"`

	// How Yummy signs webhooks sent to us (spec pending confirmation).
	WebhookSecret    string `json:"-"`
	WebhookSigHeader string `json:"webhook_signature_header"`
	WebhookSigFormat string `json:"webhook_signature_format"`

	RatePerSecond float64 `json:"rate_per_second"`
	RateBurst     int     `json:"rate_burst"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProxyKey is the credential issued by the gateway to a tenant's system.
type ProxyKey struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Label       string    `json:"label"`
	Permissions []string  `json:"permissions"`
	KeyHash     string    `json:"-"`
	Prefix      string    `json:"prefix"`
	Revoked     bool      `json:"revoked"`
	CreatedAt   time.Time `json:"created_at"`
}

// HasPermission implements Yummy's least-privilege model: "*" allows
// everything, an empty list denies everything.
func HasPermission(perms []string, want string) bool {
	if want == "" {
		return true
	}
	for _, p := range perms {
		if p == "*" || p == want {
			return true
		}
	}
	return false
}

// Webhook event lifecycle: pending -> delivering -> delivered|failed.
const (
	EventPending    = "pending"
	EventDelivering = "delivering"
	EventDelivered  = "delivered"
	EventFailed     = "failed"
)

type WebhookEvent struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	EventID       string     `json:"event_id"`
	EventType     string     `json:"event_type"`
	Payload       []byte     `json:"-"`
	ReceivedAt    time.Time  `json:"received_at"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastError     string     `json:"last_error,omitempty"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}

type EventFilter struct {
	TenantID string
	Status   string
	Limit    int
	Offset   int
}

// Store is the persistence boundary. SQLite is the default implementation;
// a MySQL implementation can be added later without touching the handlers.
type Store interface {
	Ping(ctx context.Context) error
	Close() error

	// Tenants
	CreateTenant(ctx context.Context, t *Tenant) error
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	GetTenantByWebhookToken(ctx context.Context, token string) (*Tenant, error)
	ListTenants(ctx context.Context) ([]*Tenant, error)
	UpdateTenant(ctx context.Context, t *Tenant) error
	DeleteTenant(ctx context.Context, id string) error

	// Gateway keys
	CreateProxyKey(ctx context.Context, k *ProxyKey) error
	ListProxyKeys(ctx context.Context, tenantID string) ([]*ProxyKey, error)
	GetProxyKey(ctx context.Context, id string) (*ProxyKey, error)
	RevokeProxyKey(ctx context.Context, id string) error
	// ResolveKey looks an active key up by its SHA-256 hash and returns the
	// owning active tenant together with the key.
	ResolveKey(ctx context.Context, keyHash string) (*Tenant, *ProxyKey, error)

	// Webhook events
	SaveWebhookEvent(ctx context.Context, e *WebhookEvent) error
	ClaimDueEvents(ctx context.Context, now time.Time, limit int) ([]*WebhookEvent, error)
	MarkEventDelivered(ctx context.Context, id string, at time.Time) error
	ScheduleEventRetry(ctx context.Context, id string, next time.Time, lastErr string, final bool) error
	ResetEvent(ctx context.Context, id string) error
	RecoverStaleDeliveries(ctx context.Context) error
	GetEvent(ctx context.Context, id string) (*WebhookEvent, error)
	ListEvents(ctx context.Context, f EventFilter) ([]*WebhookEvent, error)
	PurgeDelivered(ctx context.Context, before time.Time) (int64, error)
}
