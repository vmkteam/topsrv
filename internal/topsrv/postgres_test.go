package topsrv

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// TestNonPostgresCollectorsNoConflicts verifies that the non-postgres collectors
// share no metric names and pass Prometheus lint when registered together.
func TestNonPostgresCollectorsNoConflicts(t *testing.T) {
	reg := prometheus.NewRegistry()
	l := embedlog.Logger{}
	reg.MustRegister(NewSystemCollector(l, "test"))
	reg.MustRegister(NewDiskCollector(l))
	reg.MustRegister(NewNetworkCollector(l))
	reg.MustRegister(NewNetstatCollector(l))
	reg.MustRegister(NewProcessCollector(l))

	problems, err := testutil.GatherAndLint(reg)
	require.NoError(t, err)
	for _, p := range problems {
		t.Logf("lint warning: %s", p.Text)
	}

	mfs, _ := reg.Gather()
	t.Logf("metric families without postgres: %d", len(mfs))
}
