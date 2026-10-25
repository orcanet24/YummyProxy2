package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"yummygateway/internal/store"
)

// maxWebhookBody bounds the Yummy payload we accept.
const maxWebhookBody = 4 << 20

// WebhookReceiver accepts Yummy webhooks, verifies their HMAC signature,
// stores the event durably and returns 200 immediately; delivery to the
// tenant's own URL is done asynchronously by the Worker.
type WebhookReceiver struct {
	store    store.Store
	onWrite  func() // invalidates caches / pokes the worker
	interval time.Duration
}

func NewWebhookReceiver(st store.Store, interval time.Duration, onWrite func()) *WebhookReceiver {
	return &WebhookReceiver{store: st, interval: interval, onWrite: onWrite}
}

// Receive handles POST /webhooks/y/{token}.
func (h *WebhookReceiver) Receive(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown webhook endpoint")
		return
	}

	t, err := h.store.GetTenantByWebhookToken(r.Context(), token)
	if err != nil || !t.Active {
		// Do not reveal whether the token exists.
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown webhook endpoint")
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "payload too large")
		return
	}

	headerName := t.WebhookSigHeader
	if headerName == "" {
		headerName = "x-yummy-signature"
	}
	sig := r.Header.Get(headerName)
	if t.WebhookSecret != "" && t.WebhookSigFormat != SigFormatOff {
		if !VerifyIncoming(sig, t.WebhookSecret, t.WebhookSigFormat, raw) {
			slog.Warn("webhook signature rejected", "tenant", t.ID, "header", headerName)
			writeError(w, http.StatusForbidden, "INVALID_SIGNATURE", "signature verification failed")
			return
		}
	} else if t.WebhookSecret == "" {
		slog.Warn("webhook accepted without signature verification (no secret configured)",
			"tenant", t.ID)
	}

	now := nowUTC()
	id, err := newID("evt")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "could not generate event id")
		return
	}

	ev := &store.WebhookEvent{
		ID:            id,
		TenantID:      t.ID,
		EventID:       firstNonEmpty(r.Header.Get("X-Yummy-Delivery-Id"), r.Header.Get("X-Webhook-Id"), ""),
		EventType:     detectEventType(raw, r.Header.Get("X-Yummy-Event")),
		Payload:       raw,
		ReceivedAt:    now,
		Status:        store.EventPending,
		Attempts:      0,
		NextAttemptAt: now,
	}
	if err := h.store.SaveWebhookEvent(r.Context(), ev); err != nil {
		slog.Error("could not persist webhook event", "tenant", t.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "could not store event")
		return
	}
	if h.onWrite != nil {
		h.onWrite()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"received": true,
		"eventId":  ev.ID,
		"type":     ev.EventType,
		"tenant":   t.Slug,
	})
}

// detectEventType reads the "event" field of the payload (Yummy's convention)
// or falls back to a header.
func detectEventType(body []byte, headerVal string) string {
	if headerVal != "" {
		return headerVal
	}
	var probe struct {
		Event string `json:"event"`
		Type  string `json:"type"`
	}
	if err := json.Unmarshal(body, &probe); err == nil {
		if probe.Event != "" {
			return probe.Event
		}
		if probe.Type != "" {
			return probe.Type
		}
	}
	return "unknown"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Delivery worker
// ---------------------------------------------------------------------------

// backoff schedule before an event is marked failed for good.
var backoff = []time.Duration{
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
	30 * time.Minute,
	2 * time.Hour,
	6 * time.Hour,
	12 * time.Hour,
}

type Worker struct {
	store    store.Store
	timeout  time.Duration
	interval time.Duration
	batch    int
	wake     chan struct{}
}

func NewWorker(st store.Store, timeout, interval time.Duration, batch int) *Worker {
	if batch <= 0 {
		batch = 20
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &Worker{
		store:    st,
		timeout:  timeout,
		interval: interval,
		batch:    batch,
		wake:     make(chan struct{}, 1),
	}
}

// Poke asks the worker to run immediately (called when a webhook arrives).
func (w *Worker) Poke() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Worker) Run(ctx context.Context) {
	// Events left in "delivering" by a crash are safe to retry.
	if err := w.store.RecoverStaleDeliveries(ctx); err != nil {
		slog.Error("could not recover stale deliveries", "err", err)
	}
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	purge := time.NewTicker(30 * time.Minute)
	defer purge.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		case <-w.wake:
			w.tick(ctx)
		case <-purge.C:
			before := time.Now().UTC().Add(-7 * 24 * time.Hour)
			if n, err := w.store.PurgeDelivered(ctx, before); err == nil && n > 0 {
				slog.Info("purged old webhook events", "count", n)
			}
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	events, err := w.store.ClaimDueEvents(ctx, time.Now().UTC(), w.batch)
	if err != nil {
		slog.Error("could not claim webhook events", "err", err)
		return
	}
	for _, ev := range events {
		w.deliver(ctx, ev)
	}
}

func (w *Worker) deliver(ctx context.Context, ev *store.WebhookEvent) {
	t, err := w.store.GetTenant(ctx, ev.TenantID)
	if err != nil {
		_ = w.store.ScheduleEventRetry(ctx, ev.ID, time.Now().UTC(), "tenant missing", true)
		return
	}
	if !t.Active || t.CallbackURL == "" {
		_ = w.store.ScheduleEventRetry(ctx, ev.ID, time.Now().UTC(),
			"tenant inactive or has no callback URL", true)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.CallbackURL, strings.NewReader(string(ev.Payload)))
	if err != nil {
		_ = w.store.ScheduleEventRetry(ctx, ev.ID, time.Now().UTC(), "invalid callback URL: "+err.Error(), true)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Event-Id", ev.ID)
	req.Header.Set("X-Gateway-Event-Type", ev.EventType)
	req.Header.Set("X-Gateway-Delivery-Id", ev.ID)
	req.Header.Set("X-Gateway-Attempt", itoa(ev.Attempts))
	ts := time.Now().UTC()
	req.Header.Set("X-Gateway-Timestamp", itoa(int(ts.Unix())))
	if t.CallbackSecret != "" {
		req.Header.Set("X-Gateway-Signature", SignDelivery(t.CallbackSecret, ts, ev.Payload))
	}

	client := &http.Client{Timeout: w.timeout}
	resp, err := client.Do(req)
	if err != nil {
		w.retry(ctx, ev, "transport: "+err.Error())
		return
	}
	defer resp.Body.Close()

	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := w.store.MarkEventDelivered(ctx, ev.ID, time.Now().UTC()); err != nil {
			slog.Error("could not mark event delivered", "event", ev.ID, "err", err)
		}
		return
	}
	w.retry(ctx, ev, "status "+itoa(resp.StatusCode)+": "+strings.TrimSpace(string(snippet)))
}

func (w *Worker) retry(ctx context.Context, ev *store.WebhookEvent, lastErr string) {
	idx := ev.Attempts - 1 // attempts already incremented on claim
	final := idx >= len(backoff)
	next := time.Now().UTC().Add(24 * time.Hour)
	if !final && idx >= 0 {
		next = time.Now().UTC().Add(backoff[idx])
	}
	if err := w.store.ScheduleEventRetry(ctx, ev.ID, next, lastErr, final); err != nil {
		slog.Error("could not schedule retry", "event", ev.ID, "err", err)
	}
}
