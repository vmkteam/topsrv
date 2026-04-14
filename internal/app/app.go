package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vmkteam/embedlog"
)

// Config is the application configuration, loaded from TOML.
type Config struct {
	Server   ServerConfig
	Push     topsrv.PushConfig
	Update   topsrv.UpdateConfig `toml:"Update,omitempty"`
	Postgres *PostgresConfig     `toml:"Postgres,omitempty"`
	Nginx    *NginxConfig        `toml:"Nginx,omitempty"`
}

type ServerConfig struct {
	Listen string
}

type PostgresConfig struct {
	DSN string
}

type NginxConfig struct {
	StubStatusURL string
	AccessLogs    []string
	LogFormat     string   // nginx log_format string, auto-detected if empty
	ExtraLabels   []string // nginx variable names to add as metric labels

	logFormats map[string]string // path → format (populated by discovery, not from config)
}

// App is the main topsrv agent application.
type App struct {
	embedlog.Logger

	appName    string
	version    string
	cfg        Config
	srv        *http.Server
	registry   *prometheus.Registry
	pusher     *topsrv.Pusher
	closers    []io.Closer
	statusBody []byte
}

func New(appName, version string, logger embedlog.Logger, cfg Config) *App {
	body, _ := json.Marshal(map[string]string{"status": "ok", "app": appName, "version": version})
	return &App{
		Logger:     logger,
		appName:    appName,
		version:    version,
		cfg:        cfg,
		registry:   prometheus.NewRegistry(),
		statusBody: body,
	}
}

// Run starts the HTTP server and push loop.
func (a *App) Run(ctx context.Context) error {
	services := topsrv.Discover(ctx, a.Logger)

	if a.cfg.Push.Endpoint != "" {
		a.pusher = topsrv.NewPusher(a.Logger, a.appName, a.version, a.cfg.Push, a.registry)
	}

	a.registerCollectors(ctx, services)

	if a.pusher != nil {
		go a.pusher.Run(ctx)

		if a.cfg.Update.Enabled {
			updater := topsrv.NewUpdater(a.Logger, a.appName, a.version, a.cfg.Update, a.cfg.Push)
			go updater.Run(ctx)
		}
	}

	if a.cfg.Server.Listen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", promhttp.HandlerFor(a.registry, promhttp.HandlerOpts{}))
		mux.HandleFunc("GET /status", a.handleStatus)

		a.srv = &http.Server{
			Addr:         a.cfg.Server.Listen,
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		a.Print(ctx, "starting server", "listen", a.cfg.Server.Listen)
		return a.srv.ListenAndServe()
	}

	// Push-only mode: block until context is cancelled.
	a.Printf("push-only mode (no HTTP server)")
	<-ctx.Done()
	return nil
}

func (a *App) Shutdown() {
	if a.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.srv.Shutdown(ctx); err != nil {
			a.Printf("http shutdown error: %v", err)
		}
	}
	for _, c := range a.closers {
		_ = c.Close()
	}
}

func (a *App) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(a.statusBody)
}

func (a *App) registerCollectors(ctx context.Context, services []topsrv.Service) {
	for _, svc := range services {
		a.Printf("discovered %s at %s", svc.Type, svc.Instance)
	}

	// System collectors — always enabled.
	a.addCollector(topsrv.NewSystemCollector(a.Logger))
	a.addCollector(topsrv.NewDiskCollector(a.Logger))
	a.addCollector(topsrv.NewNetworkCollector(a.Logger))
	a.addCollector(topsrv.NewNetstatCollector(a.Logger))
	a.addCollector(topsrv.NewProcessCollector(a.Logger))

	// PostgreSQL — config takes precedence over discovery.
	if a.cfg.Postgres != nil {
		if pg, err := topsrv.NewPostgresCollector(a.Logger, a.cfg.Postgres.DSN); err == nil {
			a.addCollector(pg)
			a.closers = append(a.closers, pg)
			if a.pusher != nil {
				a.pusher.AddMetaProvider(pg)
			}
		} else {
			a.Printf("postgres: failed to connect: %v", err)
		}
	} else if svc := findService(services, "postgresql"); svc != nil {
		a.Printf("postgres: found at %s but no [Postgres] DSN in config — add DSN to enable monitoring", svc.Instance)
	} else {
		a.Printf("postgres: not found")
	}

	// Nginx — config or auto-discover from nginx.conf.
	a.registerNginx(ctx, services)
}

func (a *App) registerNginx(ctx context.Context, services []topsrv.Service) {
	ngxCfg := a.cfg.Nginx

	// Auto-discover from nginx.conf if no explicit config.
	if ngxCfg == nil { //nolint:nestif
		svc := findService(services, "nginx", "angie")
		if svc == nil {
			return
		}
		if svc.ConfigPath == "" {
			a.Printf("nginx: found but no config path — add [Nginx] section to config")
			return
		}

		discovered, err := nginx.DiscoverConfig(svc.ConfigPath)
		if err != nil {
			a.Printf("nginx: failed to parse %s: %v", svc.ConfigPath, err)
			return
		}

		// Build config from discovered data.
		ngxCfg = &NginxConfig{}

		// Log all discovered formats.
		for name, format := range discovered.LogFormats {
			hasTiming := strings.Contains(format, "$request_time")
			a.Printf("nginx: log_format %q (timing=%v)", name, hasTiming)
		}

		// Collect access logs that have a format with $request_time.
		// Each log gets its own parser via LogFormats map.
		logFormats := make(map[string]string) // path → format
		seen := make(map[string]bool)
		for _, entry := range discovered.AccessLogs {
			if seen[entry.Path] {
				continue
			}
			format, ok := discovered.LogFormats[entry.FormatName]
			if !ok || !strings.Contains(format, "$request_time") {
				continue
			}
			seen[entry.Path] = true
			ngxCfg.AccessLogs = append(ngxCfg.AccessLogs, entry.Path)
			logFormats[entry.Path] = format

			// Use first timing format as default.
			if ngxCfg.LogFormat == "" {
				ngxCfg.LogFormat = format
			}
		}
		ngxCfg.logFormats = logFormats

		// Discover stub_status URL.
		if discovered.StubStatusPath != "" {
			port := discovered.StubStatusPort
			if port == 0 {
				port = 80
			}
			ngxCfg.StubStatusURL = fmt.Sprintf("http://127.0.0.1:%d%s", port, discovered.StubStatusPath)
			a.Printf("nginx: auto-detected stub_status at %s", ngxCfg.StubStatusURL)
		}

		a.Printf("nginx: auto-discovered %d access logs with timing from %s", len(ngxCfg.AccessLogs), svc.ConfigPath)
	}

	// Register stub_status collector.
	if ngxCfg.StubStatusURL != "" {
		a.addCollector(nginx.NewStubCollector(a.Logger, ngxCfg.StubStatusURL))
	}

	// Register log collector (one collector for all log files).
	if len(ngxCfg.AccessLogs) > 0 {
		logC := nginx.NewLogCollector(a.Logger, nginx.LogConfig{
			LogPaths:    ngxCfg.AccessLogs,
			LogFormat:   ngxCfg.LogFormat,
			LogFormats:  ngxCfg.logFormats,
			ExtraLabels: ngxCfg.ExtraLabels,
		})
		a.addCollector(logC)
		go logC.RunPaths(ctx, ngxCfg.AccessLogs)
	}
}

func findService(services []topsrv.Service, types ...string) *topsrv.Service {
	for i := range services {
		for _, t := range types {
			if services[i].Type == t {
				return &services[i]
			}
		}
	}
	return nil
}

func (a *App) addCollector(c topsrv.Collector) {
	a.registry.MustRegister(c)
	a.Printf("collector %s registered", c.Name())
}
