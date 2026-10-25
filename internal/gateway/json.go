package gateway

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"yummygateway/internal/store"
)

// apiError is the single error envelope returned by the gateway.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = msg
	writeJSON(w, status, e)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// respondStoreError maps sentinel store errors to HTTP statuses.
func respondStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "CONFLICT", "resource already exists")
	default:
		slog.Error("store error", "err", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "internal error")
	}
}

// decodeJSON reads a JSON body (bounded) into v, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return false
	}
	return true
}

func nowUTC() time.Time { return time.Now().UTC() }

// randomID returns a short prefixed identifier, e.g. "tnt_9f2a...".
func randomID(prefix string, nBytes int) (string, error) {
	raw, err := randomHex(nBytes)
	if err != nil {
		return "", err
	}
	return prefix + "_" + raw, nil
}
