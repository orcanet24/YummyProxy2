package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Fixed-precision UTC timestamps so lexicographic order == chronological order
// in SQL comparisons.
const timeLayout = "2006-01-02T15:04:05.000"

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) time.Time {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// Open opens (and migrates) a SQLite database. WAL mode keeps readers
// non-blocking while a single writer commits batched work.
func Open(path string) (*SQLite, error) {
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("create db dir: %w", err)
			}
		}
	}

	var dsn string
	if path == ":memory:" {
		dsn = ":memory:"
	} else {
		dsn = "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection serialises all access: no SQLITE_BUSY surprises,
	// and the auth hot path is served from the in-memory cache anyway.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	for _, pragma := range []string{
		"PRAGMA busy_timeout=10000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			// journal_mode=WAL is a no-op on :memory:, ignore that one.
			if !strings.Contains(pragma, "journal_mode") {
				db.Close()
				return nil, fmt.Errorf("%s: %w", pragma, err)
			}
		}
	}

	s := &SQLite{db: db}
	if err := s.migrate(ctxBackground()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func ctxBackground() context.Context { return context.Background() }

var schema = []string{
	`CREATE TABLE IF NOT EXISTS tenants (
		id               TEXT PRIMARY KEY,
		webhook_token    TEXT NOT NULL UNIQUE,
		name             TEXT NOT NULL,
		slug             TEXT NOT NULL UNIQUE,
		active           INTEGER NOT NULL DEFAULT 1,
		callback_url     TEXT NOT NULL DEFAULT '',
		callback_secret  TEXT NOT NULL DEFAULT '',
		yummy_base_url   TEXT NOT NULL DEFAULT '',
		yummy_api_key    TEXT NOT NULL DEFAULT '',
		webhook_secret   TEXT NOT NULL DEFAULT '',
		webhook_sig_header TEXT NOT NULL DEFAULT 'x-yummy-signature',
		webhook_sig_format TEXT NOT NULL DEFAULT 'hex',
		rate_per_second  REAL NOT NULL DEFAULT 60,
		rate_burst       INTEGER NOT NULL DEFAULT 120,
		created_at       TEXT NOT NULL,
		updated_at       TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS proxy_keys (
		id          TEXT PRIMARY KEY,
		tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		label       TEXT NOT NULL DEFAULT '',
		permissions TEXT NOT NULL DEFAULT '[]',
		key_hash    TEXT NOT NULL UNIQUE,
		prefix      TEXT NOT NULL,
		revoked     INTEGER NOT NULL DEFAULT 0,
		created_at  TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_proxy_keys_tenant ON proxy_keys(tenant_id)`,
	`CREATE TABLE IF NOT EXISTS webhook_events (
		id             TEXT PRIMARY KEY,
		tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		event_id       TEXT NOT NULL DEFAULT '',
		event_type     TEXT NOT NULL DEFAULT '',
		payload        BLOB NOT NULL,
		received_at    TEXT NOT NULL,
		status         TEXT NOT NULL DEFAULT 'pending',
		attempts       INTEGER NOT NULL DEFAULT 0,
		next_attempt_at TEXT NOT NULL,
		last_error     TEXT NOT NULL DEFAULT '',
		delivered_at   TEXT
	)`,
	`CREATE INDEX IF NOT EXISTS idx_events_due ON webhook_events(status, next_attempt_at)`,
	`CREATE INDEX IF NOT EXISTS idx_events_tenant ON webhook_events(tenant_id, received_at)`,
}

func (s *SQLite) migrate(ctx context.Context) error {
	for _, stmt := range schema {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func (s *SQLite) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *SQLite) Close() error                   { return s.db.Close() }

// mapErr converts driver errors into the package's sentinel errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique constraint") || strings.Contains(msg, "constraint failed: unique") {
		return ErrConflict
	}
	return err
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

const tenantCols = `id, webhook_token, name, slug, active, callback_url, callback_secret,
	yummy_base_url, yummy_api_key, webhook_secret, webhook_sig_header, webhook_sig_format,
	rate_per_second, rate_burst, created_at, updated_at`

type scannable interface {
	Scan(dest ...any) error
}

func scanTenant(row scannable) (*Tenant, error) {
	var (
		t            Tenant
		active       int64
		rps          float64
		burst        int64
		createdAtRaw string
		updatedAtRaw string
	)
	err := row.Scan(
		&t.ID, &t.WebhookToken, &t.Name, &t.Slug, &active,
		&t.CallbackURL, &t.CallbackSecret, &t.YummyBaseURL, &t.YummyAPIKey,
		&t.WebhookSecret, &t.WebhookSigHeader, &t.WebhookSigFormat,
		&rps, &burst, &createdAtRaw, &updatedAtRaw,
	)
	if err != nil {
		return nil, mapErr(err)
	}
	t.Active = active != 0
	t.RatePerSecond = rps
	t.RateBurst = int(burst)
	t.CreatedAt = parseTime(createdAtRaw)
	t.UpdatedAt = parseTime(updatedAtRaw)
	return &t, nil
}

func (s *SQLite) CreateTenant(ctx context.Context, t *Tenant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenants (`+tenantCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.WebhookToken, t.Name, t.Slug, b2i(t.Active),
		t.CallbackURL, t.CallbackSecret, t.YummyBaseURL, t.YummyAPIKey,
		t.WebhookSecret, t.WebhookSigHeader, t.WebhookSigFormat,
		t.RatePerSecond, t.RateBurst, fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt),
	)
	return mapErr(err)
}

func (s *SQLite) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = ?`, id)
	return scanTenant(row)
}

func (s *SQLite) GetTenantByWebhookToken(ctx context.Context, token string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+tenantCols+` FROM tenants WHERE webhook_token = ?`, token)
	return scanTenant(row)
}

func (s *SQLite) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY created_at ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []*Tenant{}
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateTenant(ctx context.Context, t *Tenant) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tenants SET
			webhook_token=?, name=?, slug=?, active=?, callback_url=?, callback_secret=?,
			yummy_base_url=?, yummy_api_key=?, webhook_secret=?, webhook_sig_header=?,
			webhook_sig_format=?, rate_per_second=?, rate_burst=?, updated_at=?
		WHERE id = ?`,
		t.WebhookToken, t.Name, t.Slug, b2i(t.Active), t.CallbackURL, t.CallbackSecret,
		t.YummyBaseURL, t.YummyAPIKey, t.WebhookSecret, t.WebhookSigHeader,
		t.WebhookSigFormat, t.RatePerSecond, t.RateBurst, fmtTime(t.UpdatedAt), t.ID,
	)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteTenant(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Gateway keys
// ---------------------------------------------------------------------------

const keyCols = `id, tenant_id, label, permissions, key_hash, prefix, revoked, created_at`

func scanKey(row scannable) (*ProxyKey, error) {
	var (
		k         ProxyKey
		permsJSON string
		revoked   int64
		created   string
	)
	err := row.Scan(&k.ID, &k.TenantID, &k.Label, &permsJSON, &k.KeyHash, &k.Prefix, &revoked, &created)
	if err != nil {
		return nil, mapErr(err)
	}
	if permsJSON != "" {
		_ = json.Unmarshal([]byte(permsJSON), &k.Permissions)
	}
	if k.Permissions == nil {
		k.Permissions = []string{}
	}
	k.Revoked = revoked != 0
	k.CreatedAt = parseTime(created)
	return &k, nil
}

func (s *SQLite) CreateProxyKey(ctx context.Context, k *ProxyKey) error {
	perms, err := json.Marshal(k.Permissions)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO proxy_keys (`+keyCols+`)
		VALUES (?,?,?,?,?,?,?,?)`,
		k.ID, k.TenantID, k.Label, string(perms), k.KeyHash, k.Prefix, b2i(k.Revoked), fmtTime(k.CreatedAt),
	)
	return mapErr(err)
}

func (s *SQLite) ListProxyKeys(ctx context.Context, tenantID string) ([]*ProxyKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keyCols+` FROM proxy_keys WHERE tenant_id = ? ORDER BY created_at ASC`, tenantID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []*ProxyKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLite) GetProxyKey(ctx context.Context, id string) (*ProxyKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM proxy_keys WHERE id = ?`, id)
	return scanKey(row)
}

func (s *SQLite) RevokeProxyKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE proxy_keys SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) ResolveKey(ctx context.Context, keyHash string) (*Tenant, *ProxyKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+keyCols+` FROM proxy_keys WHERE key_hash = ? AND revoked = 0`, keyHash)
	k, err := scanKey(row)
	if err != nil {
		return nil, nil, err
	}
	t, err := s.GetTenant(ctx, k.TenantID)
	if err != nil {
		return nil, nil, err
	}
	if !t.Active {
		return nil, nil, ErrNotFound
	}
	return t, k, nil
}

// ---------------------------------------------------------------------------
// Webhook events
// ---------------------------------------------------------------------------

const eventCols = `id, tenant_id, event_id, event_type, payload, received_at,
	status, attempts, next_attempt_at, last_error, delivered_at`

func scanEvent(row scannable) (*WebhookEvent, error) {
	var (
		e         WebhookEvent
		received  string
		next      string
		delivered sql.NullString
	)
	err := row.Scan(&e.ID, &e.TenantID, &e.EventID, &e.EventType, &e.Payload,
		&received, &e.Status, &e.Attempts, &next, &e.LastError, &delivered)
	if err != nil {
		return nil, mapErr(err)
	}
	e.ReceivedAt = parseTime(received)
	e.NextAttemptAt = parseTime(next)
	if delivered.Valid && delivered.String != "" {
		t := parseTime(delivered.String)
		e.DeliveredAt = &t
	}
	return &e, nil
}

func (s *SQLite) SaveWebhookEvent(ctx context.Context, e *WebhookEvent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_events (`+eventCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.TenantID, e.EventID, e.EventType, e.Payload,
		fmtTime(e.ReceivedAt), e.Status, e.Attempts, fmtTime(e.NextAttemptAt),
		e.LastError, nullableTime(e.DeliveredAt),
	)
	return mapErr(err)
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

// ClaimDueEvents atomically moves up to `limit` due events into "delivering"
// and returns them for the delivery worker.
func (s *SQLite) ClaimDueEvents(ctx context.Context, now time.Time, limit int) ([]*WebhookEvent, error) {
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, mapErr(err)
	}
	defer tx.Rollback() //nolint:errcheck

	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM webhook_events
		WHERE status = ? AND next_attempt_at <= ?
		ORDER BY next_attempt_at ASC
		LIMIT ?`, EventPending, fmtTime(now), limit)
	if err != nil {
		return nil, mapErr(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE webhook_events SET status = ?, attempts = attempts + 1 WHERE id IN (`+placeholders+`)`,
		append([]any{EventDelivering}, args...)...); err != nil {
		return nil, mapErr(err)
	}

	out := make([]*WebhookEvent, 0, len(ids))
	q := `SELECT ` + eventCols + ` FROM webhook_events WHERE id IN (` + placeholders + `)`
	rows2, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows2.Close()
	for rows2.Next() {
		e, err := scanEvent(rows2)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

func (s *SQLite) MarkEventDelivered(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE webhook_events SET status = ?, delivered_at = ?, last_error = '' WHERE id = ?`,
		EventDelivered, fmtTime(at), id)
	return mapErr(err)
}

func (s *SQLite) ScheduleEventRetry(ctx context.Context, id string, next time.Time, lastErr string, final bool) error {
	status := EventPending
	if final {
		status = EventFailed
	}
	if len(lastErr) > 500 {
		lastErr = lastErr[:500]
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE webhook_events SET status = ?, next_attempt_at = ?, last_error = ? WHERE id = ?`,
		status, fmtTime(next), lastErr, id)
	return mapErr(err)
}

func (s *SQLite) ResetEvent(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE webhook_events SET status = ?, attempts = 0, next_attempt_at = ?, last_error = ''
		WHERE id = ?`, EventPending, fmtTime(time.Now().UTC()), id)
	if err != nil {
		return mapErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RecoverStaleDeliveries(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webhook_events SET status = ? WHERE status = ?`, EventPending, EventDelivering)
	return mapErr(err)
}

func (s *SQLite) GetEvent(ctx context.Context, id string) (*WebhookEvent, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+eventCols+` FROM webhook_events WHERE id = ?`, id)
	return scanEvent(row)
}

func (s *SQLite) ListEvents(ctx context.Context, f EventFilter) ([]*WebhookEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `SELECT ` + eventCols + ` FROM webhook_events WHERE 1=1`
	var args []any
	if f.TenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, f.TenantID)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY received_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, max(f.Offset, 0))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []*WebhookEvent{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) PurgeDelivered(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM webhook_events WHERE status IN (?, ?) AND received_at < ?`,
		EventDelivered, EventFailed, fmtTime(before))
	if err != nil {
		return 0, mapErr(err)
	}
	return res.RowsAffected()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
