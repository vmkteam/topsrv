package security

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchedule(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	const interval = 6 * time.Hour

	t.Run("first pass after the start delay, then every interval ±10%", func(t *testing.T) {
		s := newSchedule(t0, interval, 3*time.Minute)

		_, ok := s.due(t0.Add(2 * time.Minute))
		assert.False(t, ok)
		assert.Equal(t, t0.Add(3*time.Minute), s.wake())

		trig, ok := s.due(t0.Add(3 * time.Minute))
		require.True(t, ok)
		assert.Equal(t, Trigger{Cause: triggerStart}, trig, "a full pass has no section list")

		next := s.wake().Sub(t0.Add(3 * time.Minute))
		assert.InDelta(t, float64(interval), float64(next), float64(interval/10))
		trig, ok = s.due(s.wake())
		require.True(t, ok)
		assert.Equal(t, triggerInterval, trig.Cause)
	})

	t.Run("triggers coalesce and wait 5 minutes after the last snapshot", func(t *testing.T) {
		s := newSchedule(t0, interval, 0)
		_, ok := s.due(t0)
		require.True(t, ok)

		s.pending.add(Trigger{Cause: "inotify", Sections: []string{SectionSSHD}})
		s.pending.add(Trigger{Cause: "pkgdb", Sections: []string{SectionFIM, SectionSSHD}})
		assert.Equal(t, t0.Add(minUnscheduledGap), s.wake())

		_, ok = s.due(t0.Add(time.Minute))
		assert.False(t, ok, "rate limited")

		trig, ok := s.due(t0.Add(minUnscheduledGap))
		require.True(t, ok)
		assert.Equal(t, Trigger{Cause: "inotify", Sections: []string{SectionSSHD, SectionFIM}}, trig)

		s.pending.add(Trigger{Cause: "inotify", Sections: []string{SectionSSHD}})
		_, ok = s.due(t0.Add(minUnscheduledGap + time.Minute))
		assert.False(t, ok, "the unscheduled pass counts as the last snapshot")
	})

	t.Run("the full pass absorbs pending triggers", func(t *testing.T) {
		s := newSchedule(t0, interval, time.Minute)
		s.pending.add(Trigger{Cause: "inotify", Sections: []string{SectionSSHD}})

		_, ok := s.due(t0.Add(30 * time.Second))
		assert.False(t, ok, "triggers wait for the first full pass")
		assert.Equal(t, t0.Add(time.Minute), s.wake())

		trig, ok := s.due(t0.Add(time.Minute))
		require.True(t, ok)
		assert.Equal(t, Trigger{Cause: triggerStart}, trig)
		assert.True(t, s.pending.empty())
	})

	t.Run("a trigger without sections makes the pass full, in either order", func(t *testing.T) {
		for name, triggers := range map[string][]Trigger{
			"full first":    {{Cause: "overflow"}, {Cause: "inotify", Sections: []string{SectionSSHD}}},
			"partial first": {{Cause: "inotify", Sections: []string{SectionSSHD}}, {Cause: "overflow"}},
		} {
			s := newSchedule(t0, interval, 0)
			_, ok := s.due(t0)
			require.True(t, ok)
			for _, tr := range triggers {
				s.pending.add(tr)
			}

			trig, ok := s.due(t0.Add(minUnscheduledGap))
			require.True(t, ok, name)
			assert.Nil(t, trig.Sections, name)
			assert.Equal(t, triggers[0].Cause, trig.Cause, name)
		}
	})

	t.Run("the scheduled pass is never rate limited", func(t *testing.T) {
		s := newSchedule(t0, interval, 0)
		_, ok := s.due(t0)
		require.True(t, ok)
		s.pending.add(Trigger{Cause: "inotify", Sections: []string{SectionSSHD}})
		_, ok = s.due(t0.Add(minUnscheduledGap))
		require.True(t, ok)

		s.nextFull = t0.Add(minUnscheduledGap + time.Minute)
		trig, ok := s.due(s.nextFull)
		require.True(t, ok, "a minute after an unscheduled snapshot")
		assert.Equal(t, triggerInterval, trig.Cause)
	})
}

func TestStartDelay(t *testing.T) {
	for range 100 {
		d := startDelay()
		assert.GreaterOrEqual(t, d, time.Minute)
		assert.Less(t, d, 5*time.Minute)
	}
}
