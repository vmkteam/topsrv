package topsrv

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// collectAndLint registers a collector, gathers metrics, and runs linter checks.
func collectAndLint(t *testing.T, c Collector) int {
	t.Helper()

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	problems, err := testutil.GatherAndLint(reg)
	require.NoError(t, err, "%s: gather error", c.Name())
	for _, p := range problems {
		t.Logf("%s: lint warning: %s", c.Name(), p.Text)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err, "%s: gather error", c.Name())
	return len(mfs)
}

// requireMetric checks that a metric with the given name prefix exists in the registry.
func requireMetric(t *testing.T, reg *prometheus.Registry, name string) {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), name) {
			return
		}
	}
	t.Errorf("metric %q not found", name)
}

func TestAllCollectorsInRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	l := embedlog.Logger{}
	for _, c := range []Collector{
		NewSystemCollector(l),
		NewDiskCollector(l),
		NewNetworkCollector(l),
		NewNetstatCollector(l),
		NewProcessCollector(l),
	} {
		reg.MustRegister(c)
	}

	mfs, err := reg.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, mf := range mfs {
		name := mf.GetName()
		assert.False(t, names[name], "duplicate metric name: %s", name)
		names[name] = true
		assert.True(t, strings.HasPrefix(name, "topsrv_"), "metric %q missing topsrv_ prefix", name)
	}
	t.Logf("total metric families: %d", len(mfs))
}
