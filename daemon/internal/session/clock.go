package session

import "time"

// Clock is the injectable time source. The TTL reaper and age/ttl_remaining
// accounting go through it so tests drive expiry deterministically instead of
// sleeping real wall-clock time (a blocking time.Now would make the reaper
// untestable — shared-engineering: resource discipline + testable core).
type Clock interface {
	Now() time.Time
}

// systemClock is the production Clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock returns the wall-clock Clock used in production.
func SystemClock() Clock { return systemClock{} }
