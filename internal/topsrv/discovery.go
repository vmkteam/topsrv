package topsrv

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/vmkteam/embedlog"
)

// serviceNames maps process names to service types.
var serviceNames = map[string]string{
	"postgres":     "postgresql",
	"postmaster":   "postgresql",
	"nginx":        "nginx",
	"angie":        "angie",
	"redis-server": "redis",
	"pgbouncer":    "pgbouncer",
	"php-fpm":      "php-fpm",
}

// defaultInstances maps service types to default listen addresses.
var defaultInstances = map[string]string{
	"postgresql": "127.0.0.1:5432",
	"nginx":      "127.0.0.1:80",
	"angie":      "127.0.0.1:80",
	"redis":      "127.0.0.1:6379",
	"pgbouncer":  "127.0.0.1:6432",
}

// Discover scans processes and detects running services.
func Discover(ctx context.Context, logger embedlog.Logger) []Service {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		logger.Error(ctx, "discovery: failed to list processes", "error", err)
		return nil
	}

	seen := make(map[string]bool)
	var services []Service

	for _, p := range procs {
		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}

		svcType, ok := serviceNames[name]
		if !ok || seen[svcType] {
			continue
		}
		seen[svcType] = true

		svc := Service{
			Type:     svcType,
			Instance: defaultInstances[svcType],
		}

		// Try to extract config path from cmdline.
		if args, err := p.CmdlineSliceWithContext(ctx); err == nil {
			svc.ConfigPath = findConfigPath(svcType, args)
		}

		services = append(services, svc)
	}

	return services
}

// findConfigPath extracts config file path from process arguments.
func findConfigPath(svcType string, args []string) string {
	switch svcType {
	case "nginx", "angie":
		// nginx -c /path/to/nginx.conf
		for i, arg := range args {
			if arg == "-c" && i+1 < len(args) {
				return args[i+1]
			}
		}
		if svcType == "angie" {
			return "/etc/angie/angie.conf"
		}
		return "/etc/nginx/nginx.conf"

	case "postgresql":
		// postgres -c config_file=/path OR -D /datadir
		for i, arg := range args {
			if arg == "-D" && i+1 < len(args) {
				return args[i+1] + "/postgresql.conf"
			}
		}
	}

	return ""
}
