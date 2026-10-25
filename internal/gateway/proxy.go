package gateway

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"yummygateway/internal/store"
)

// sellerPrefix is where Yummy exposes its seller API.
const sellerPrefix = "/seller-api/v1"

// headers forwarded from the client to Yummy (plus x-api-key, always).
var forwardHeaders = []string{
	"Content-Type",
	"Accept",
	"Idempotency-Key",
	"X-Idempotency-Key",
	"X-Correlation-Id",
	"X-Request-Id",
}

// headers copied back from Yummy to the client.
var returnHeaders = []string{
	"Content-Type",
	"Retry-After",
	"X-Request-Id",
	"X-Correlation-Id",
}

// Proxy is the pass-through layer: it terminates the tenant's gateway key,
// injects that tenant's Yummy x-api-key and forwards the call upstream.
type Proxy struct {
	store   store.Store
	client  *http.Client
	maxBody int64
}

func NewProxy(st store.Store, timeout time.Duration, maxBody int64) *Proxy {
	return &Proxy{
		store:   st,
		client:  &http.Client{Timeout: timeout},
		maxBody: maxBody,
	}
}

// ---- typed endpoints (one per Yummy route) ---------------------------------

func (p *Proxy) StockSync(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/stock/sync")
}

func (p *Proxy) StockList(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/stock")
}

func (p *Proxy) PriceUpdate(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/sku")
}

func (p *Proxy) Orders(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/orders")
}

func (p *Proxy) ChatMessages(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/chat/messages")
}

func (p *Proxy) ChatHistory(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/chat/"+r.PathValue("chatId")+"/messages")
}

// ChatReply answers in a chat (POST /v1/chat/{chatId}/messages).
func (p *Proxy) ChatReply(w http.ResponseWriter, r *http.Request) {
	p.forward(w, r, sellerPrefix+"/chat/"+r.PathValue("chatId")+"/messages")
}

// Passthrough forwards any other seller-api route: /v1/yummy/<rest> goes to
// /seller-api/v1/<rest>. Permission is inferred from the path so a key limited
// to stock cannot smuggle a price update through here.
func (p *Proxy) Passthrough(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("path")
	if rest == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown gateway path")
		return
	}
	p.forward(w, r, sellerPrefix+"/"+strings.TrimPrefix(rest, "/"))
}

// ---- core forwarding -------------------------------------------------------

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, upstreamPath string) {
	t, _ := tenantFrom(r.Context())
	if t == nil {
		writeError(w, http.StatusUnauthorized, "INVALID_API_KEY", "unknown tenant")
		return
	}
	if t.YummyBaseURL == "" {
		writeError(w, http.StatusServiceUnavailable, "NO_UPSTREAM",
			"this tenant has no Yummy base URL configured")
		return
	}
	if t.YummyAPIKey == "" {
		writeError(w, http.StatusServiceUnavailable, "NO_CREDENTIAL",
			"this tenant has no Yummy API key configured")
		return
	}

	// Read and bound the body so the upstream request gets a known length.
	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBody))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE",
				"request body exceeds the gateway limit")
			return
		}
		body = bytes.NewReader(raw)
	}

	target := strings.TrimRight(t.YummyBaseURL, "/") + upstreamPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "UPSTREAM_ERROR", "could not build upstream request")
		return
	}
	req.Header.Set("x-api-key", t.YummyAPIKey)
	req.Header.Set("Accept", "application/json")
	for _, h := range forwardHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if req.Header.Get("Content-Type") == "" && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		slog.Error("upstream request failed",
			"tenant", t.ID, "path", upstreamPath, "err", err)
		writeError(w, http.StatusBadGateway, "UPSTREAM_ERROR",
			"the Yummy API could not be reached")
		return
	}
	defer resp.Body.Close()

	for _, h := range returnHeaders {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("X-Gateway-Upstream-Status", strconv.Itoa(resp.StatusCode))
	w.Header().Set("X-Gateway-Duration-Ms", strconv.Itoa(int(time.Since(start).Milliseconds())))

	w.WriteHeader(resp.StatusCode)
	// Yummy responses are small JSON documents; cap what we relay.
	if _, err := io.Copy(w, io.LimitReader(resp.Body, p.maxBody)); err != nil {
		slog.Warn("could not relay upstream body", "tenant", t.ID, "err", err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
