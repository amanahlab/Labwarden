package api

import (
	"net/netip"
	"sync"
	"time"
)

const (
	maxTrackedClients = 10000
	// forgetAfter is how long a client must stay quiet, once any lockout
	// has run out, before its failures are forgotten.
	forgetAfter = time.Hour
	// fullWait is what a new client is told while the table is full.
	fullWait = time.Minute
)

// loginLimiter locks a client out for a while after repeated failures. Its
// table is bounded: when it is full, quiet clients are forgotten and, if that
// is not enough, new clients are refused until room frees up. It never
// starts over, which would hand every locked-out client a fresh start.
type loginLimiter struct {
	mu     sync.Mutex
	hits   map[string]*attempts
	max    int
	pruned time.Time
	now    func() time.Time
}

type attempts struct {
	n           int
	until, last time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{hits: map[string]*attempts{}, max: maxTrackedClients, now: time.Now}
}

// limitKey groups IPv6 clients by /64, the block a single site usually gets:
// otherwise one client could try from a fresh address every time.
func limitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() {
		return ip
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// blocked returns how long the client must wait before trying again.
func (l *loginLimiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if a, ok := l.hits[limitKey(ip)]; ok {
		return max(a.until.Sub(now), 0)
	}
	if !l.room(now) {
		return fullWait
	}
	return 0
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := limitKey(ip)
	a, ok := l.hits[key]
	if ok && a.stale(now) {
		a.n = 0
	}
	if !ok {
		if !l.room(now) {
			return // blocked already refused it unless the table filled up meanwhile
		}
		a = &attempts{}
		l.hits[key] = a
	}
	a.n++
	a.last = now
	if a.n >= 5 {
		a.until = now.Add(time.Duration(a.n-4) * 30 * time.Second)
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, limitKey(ip))
}

// room reports whether a new client fits, forgetting quiet clients (at most
// once a minute) when the table is full.
func (l *loginLimiter) room(now time.Time) bool {
	if len(l.hits) < l.max {
		return true
	}
	if now.Sub(l.pruned) >= time.Minute {
		l.pruned = now
		for k, a := range l.hits {
			if a.stale(now) {
				delete(l.hits, k)
			}
		}
	}
	return len(l.hits) < l.max
}

func (a *attempts) stale(now time.Time) bool {
	return !now.Before(a.until) && now.Sub(a.last) >= forgetAfter
}

// failBudget is a token bucket shared by all clients. It caps how fast the
// one admin password can be guessed from many addresses at once.
type failBudget struct {
	mu     sync.Mutex
	size   float64
	tokens float64
	every  time.Duration // one token comes back each interval
	last   time.Time
	warned time.Time
	now    func() time.Time
}

func newFailBudget(n int, window time.Duration) *failBudget {
	return &failBudget{size: float64(n), tokens: float64(n), every: window / time.Duration(n), now: time.Now}
}

func (b *failBudget) refill(now time.Time) {
	if !b.last.IsZero() {
		b.tokens = min(b.size, b.tokens+float64(now.Sub(b.last))/float64(b.every))
	}
	b.last = now
}

// wait returns how long until a failure may be spent again.
func (b *failBudget) wait() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.refill(now)
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) * float64(b.every))
}

// spend records a failure. It returns true when the budget has run out and
// nobody has been told so in the last window, so callers warn once, not on
// every refused attempt.
func (b *failBudget) spend() (warn bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.refill(now)
	b.tokens = max(b.tokens-1, 0)
	window := time.Duration(b.size) * b.every
	if b.tokens < 1 && now.Sub(b.warned) >= window {
		b.warned = now
		return true
	}
	return false
}
