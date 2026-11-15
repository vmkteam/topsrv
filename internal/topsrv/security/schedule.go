package security

import (
	"math/rand/v2"
	"slices"
	"time"
)

// minUnscheduledGap spaces out snapshots of unscheduled passes; the
// scheduled snapshot is always sent.
const minUnscheduledGap = 5 * time.Minute

// Values of Data.Trigger.
const (
	triggerStart    = "start"
	triggerInterval = "interval"
)

// Trigger asks for an unscheduled pass of some sections, e.g. after an
// inotify event on /etc/ssh. No sections means all of them (an inotify
// queue overflow).
type Trigger struct {
	Cause    string
	Sections []string
}

// triggerSet coalesces triggers: one pass covers them all. The first cause
// is kept; a trigger without sections makes the set a full pass.
type triggerSet struct {
	cause    string
	sections []string
	all      bool
}

func (p *triggerSet) empty() bool { return !p.all && len(p.sections) == 0 }

func (p *triggerSet) add(t Trigger) {
	if p.empty() {
		p.cause = t.Cause
	}
	if len(t.Sections) == 0 {
		p.all = true
	}
	for _, sec := range t.Sections {
		if !slices.Contains(p.sections, sec) {
			p.sections = append(p.sections, sec)
		}
	}
}

// merge adds every trigger of o.
func (p *triggerSet) merge(o triggerSet) {
	if !o.empty() {
		p.add(o.trigger())
	}
}

func (p *triggerSet) trigger() Trigger {
	if p.all {
		return Trigger{Cause: p.cause}
	}
	return Trigger{Cause: p.cause, Sections: p.sections}
}

// schedule decides what the collector runs and when. It holds no clock:
// every method takes now, so tests drive it directly.
type schedule struct {
	interval     time.Duration
	nextFull     time.Time
	lastSnapshot time.Time // zero until the first full pass
	pending      triggerSet
}

func newSchedule(now time.Time, interval, startDelay time.Duration) *schedule {
	return &schedule{interval: interval, nextFull: now.Add(startDelay)}
}

// wake returns when the collector should next look at the schedule.
func (s *schedule) wake() time.Time {
	if s.pending.empty() || s.lastSnapshot.IsZero() {
		return s.nextFull
	}
	if at := s.lastSnapshot.Add(minUnscheduledGap); at.Before(s.nextFull) {
		return at
	}
	return s.nextFull
}

// due returns the pass to run at now, if any: the full pass when it is
// time, which also covers pending triggers; otherwise the pending trigger
// once minUnscheduledGap has passed since the last snapshot. Triggers wait
// for the first full pass: before it, the sections they skip have nothing
// in the cache.
func (s *schedule) due(now time.Time) (Trigger, bool) {
	switch {
	case !now.Before(s.nextFull):
		t := Trigger{Cause: triggerInterval}
		if s.lastSnapshot.IsZero() {
			t.Cause = triggerStart
		}
		s.nextFull = now.Add(s.interval + jitter(s.interval))
		s.pending = triggerSet{}
		s.lastSnapshot = now
		return t, true
	case !s.pending.empty() && !s.lastSnapshot.IsZero() && !now.Before(s.lastSnapshot.Add(minUnscheduledGap)):
		t := s.pending.trigger()
		s.pending = triggerSet{}
		s.lastSnapshot = now
		return t, true
	}
	return Trigger{}, false
}

// jitter returns a uniform perturbation within ±10% of base, so agents
// started together drift apart.
func jitter(base time.Duration) time.Duration {
	span := int64(base) / 10
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(2*span) - span)
}

// startDelay spreads the first pass 1–5 minutes after start, away from the
// packages scan.
func startDelay() time.Duration {
	return time.Minute + time.Duration(rand.Int64N(int64(4*time.Minute)))
}
