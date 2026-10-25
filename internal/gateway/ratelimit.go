package gateway

import (
	"sync"
	"time"
)

// Limiter is an in-memory token bucket per tenant. Cheap, no dependencies and
// enough for a gateway serving a handful of tenants on one node.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	rps    float64
	burst  float64
}

func NewLimiter() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket), lastGC: time.Now()}
}

// Allow reports whether a request under the given id may proceed at rps/burst.
// rps <= 0 disables limiting for that tenant.
func (l *Limiter) Allow(id string, rps float64, burst int) bool {
	if rps <= 0 {
		return true
	}
	if burst <= 0 {
		burst = 1
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[id]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now, rps: rps, burst: float64(burst)}
		l.buckets[id] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rps
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	b.rps = rps
	b.burst = float64(burst)

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Cleanup drops idle buckets so the map cannot grow without bound.
func (l *Limiter) Cleanup(maxIdle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	for id, b := range l.buckets {
		if now.Sub(b.last) > maxIdle {
			delete(l.buckets, id)
		}
	}
}
