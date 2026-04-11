package topsrv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmkteam/embedlog"
)

func TestDiscover(t *testing.T) {
	services := Discover(context.Background(), embedlog.Logger{})
	t.Logf("discovered %d services", len(services))
	for _, svc := range services {
		t.Logf("  %s at %s (config: %s)", svc.Type, svc.Instance, svc.ConfigPath)
	}

	for _, svc := range services {
		if svc.Type == "postgresql" {
			assert.Equal(t, "127.0.0.1:5432", svc.Instance)
		}
	}
}

func TestDiscoverNoDuplicates(t *testing.T) {
	services := Discover(context.Background(), embedlog.Logger{})
	seen := make(map[string]bool)
	for _, svc := range services {
		assert.False(t, seen[svc.Type], "duplicate service type: %s", svc.Type)
		seen[svc.Type] = true
	}
}

func TestFindConfigPath(t *testing.T) {
	tests := []struct {
		svcType string
		args    []string
		want    string
	}{
		{"nginx", []string{"nginx", "-c", "/etc/nginx/custom.conf"}, "/etc/nginx/custom.conf"},
		{"nginx", []string{"nginx"}, "/etc/nginx/nginx.conf"},
		{"angie", []string{"angie"}, "/etc/angie/angie.conf"},
		{"postgresql", []string{"postgres", "-D", "/var/lib/pgsql/data"}, "/var/lib/pgsql/data/postgresql.conf"},
		{"postgresql", []string{"postgres"}, ""},
		{"redis", []string{"redis-server"}, ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, findConfigPath(tt.svcType, tt.args), "findConfigPath(%s, %v)", tt.svcType, tt.args)
	}
}
