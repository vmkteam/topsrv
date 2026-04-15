package smart

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestCollectorName(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, "5m")
	assert.Equal(t, "smart", c.Name())
}

func TestCollectorLint(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, "5m")

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	problems, err := testutil.GatherAndLint(reg)
	require.NoError(t, err)
	for _, p := range problems {
		t.Logf("lint: %s", p.Text)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)
	t.Logf("smart: %d metric families", len(mfs))
}

func TestCollectorDefaultInterval(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, "")
	assert.Equal(t, defaultInterval, c.interval)
}

func TestCollectorCustomInterval(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, "10m")
	assert.Equal(t, 10*defaultInterval/5, c.interval)
}

func TestCollectorInvalidInterval(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, "bad")
	assert.Equal(t, defaultInterval, c.interval)
}

func TestCollectorEmptyCollect(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, "5m")

	// Before any scan, Collect should not panic and return nothing.
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	assert.Empty(t, ch)
}
