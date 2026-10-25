package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds every runtime setting of the gateway. All values come from
// environment variables so the same image runs in Docker, compose or bare metal.
type Config struct {
	// ListenAddr is the HTTP bind address, e.g. ":8080".
	ListenAddr string
	// DBPath is the SQLite file. Use ":memory:" for tests.
	DBPath string
	// AdminToken protects the /admin API. When empty the admin API is disabled.
	AdminToken string
	// PublicBaseURL is the external URL of this gateway; used to build the
	// webhook URL handed to each tenant (e.g. https://gw.example.com).
	PublicBaseURL string

	UpstreamTimeout time.Duration
	DeliverTimeout  time.Duration
	WorkerInterval  time.Duration
	WorkerBatch     int
	EventRetention  time.Duration

	MaxBodyBytes int64
	AuthCacheTTL time.Duration
	DefaultRPS   float64
	DefaultBurst int
	LogLevel     string
	LogJSON      bool
}

func Load() Config {
	return Config{
		ListenAddr:      env("GATEWAY_LISTEN", ":8080"),
		DBPath:          env("GATEWAY_DB_PATH", "./data/gateway.db"),
		AdminToken:      os.Getenv("GATEWAY_ADMIN_TOKEN"),
		PublicBaseURL:   env("GATEWAY_PUBLIC_BASE_URL", "http://localhost:8080"),
		UpstreamTimeout: envDur("GATEWAY_UPSTREAM_TIMEOUT", 30*time.Second),
		DeliverTimeout:  envDur("GATEWAY_DELIVER_TIMEOUT", 10*time.Second),
		WorkerInterval:  envDur("GATEWAY_WORKER_INTERVAL", time.Second),
		WorkerBatch:     envInt("GATEWAY_WORKER_BATCH", 20),
		EventRetention:  envDur("GATEWAY_EVENT_RETENTION", 7*24*time.Hour),
		MaxBodyBytes:    int64(envInt("GATEWAY_MAX_BODY_BYTES", 4<<20)),
		AuthCacheTTL:    envDur("GATEWAY_AUTH_CACHE_TTL", 15*time.Second),
		DefaultRPS:      envFloat("GATEWAY_DEFAULT_RPS", 60),
		DefaultBurst:    envInt("GATEWAY_DEFAULT_BURST", 120),
		LogLevel:        env("GATEWAY_LOG_LEVEL", "info"),
		LogJSON:         envBool("GATEWAY_LOG_JSON", false),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
