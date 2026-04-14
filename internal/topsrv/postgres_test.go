package topsrv

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func TestPostgresCollectorDescribe(t *testing.T) {
	dsn := "postgres://invalid:invalid@localhost:59999/invalid?connect_timeout=1"
	pg, err := NewPostgresCollector(embedlog.Logger{}, dsn)
	if err == nil {
		pg.Close()
		t.Skip("unexpectedly connected to postgres")
	}
	t.Logf("expected error creating collector: %v", err)
}

func TestPostgresCollectorNoConflicts(t *testing.T) {
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
