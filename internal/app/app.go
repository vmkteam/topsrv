package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/angie"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
	"github.com/vmkteam/topsrv/internal/topsrv/postgres"
	"github.com/vmkteam/topsrv/internal/topsrv/smart"

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
	Angie    *AngieConfig        `toml:"Angie,omitempty"`
	Smart    *smart.Config       `toml:"Smart,omitempty"`
}

type ServerConfig struct {
	Listen string
}

type PostgresConfig struct {
	DSN      string
	Disabled bool // skip PostgreSQL monitoring even if discovery finds a local process
}

// AngieConfig holds Angie-specific monitoring settings.
type AngieConfig struct {
	StatusURL     string   // JSON API URL, e.g. "http://127.0.0.1:8080/status/"
	StubStatusURL string   // Fallback stub_status URL
	AccessLogs    []string // Access log file paths
	LogFormat     string   // nginx/angie log_format string, auto-detected if empty
	ExtraLabels   []string // Log field names to add as metric labels

	logCfg nginx.LogConfig // populated by discovery
}

type NginxConfig struct {
	StubStatusURL string
	AccessLogs    []string
	LogFormat     string   // nginx log_format string, auto-detected if empty
	ExtraLabels   []string // nginx variable names to add as metric labels

	logCfg nginx.LogConfig // populated by discovery
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
	a.Print(ctx, "starting", "app", a.appName, "version", a.version)

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
	a.Print(ctx, "push-only mode (no HTTP server)")
	<-ctx.Done()
	return nil
}

func (a *App) Shutdown() {
	if a.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.srv.Shutdown(ctx); err != nil {
			a.Error(ctx, "http shutdown error", "error", err)
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
		a.Print(ctx, "discovered service", "type", svc.Type, "instance", svc.Instance)
	}

	// System collectors — always enabled.
	a.addCollector(topsrv.NewSystemCollector(a.Logger, a.version))
	a.addCollector(topsrv.NewDiskCollector(a.Logger))
	a.addCollector(topsrv.NewNetworkCollector(a.Logger))
	a.addCollector(topsrv.NewNetstatCollector(a.Logger))
	a.addCollector(topsrv.NewProcessCollector(a.Logger))

	// PostgreSQL — config takes precedence over discovery.
	a.registerPostgres(ctx, services)

	// Angie — config or auto-discover from angie.conf.
	// Nginx — config or auto-discover from nginx.conf.
	if a.cfg.Angie != nil {
		a.registerAngie(ctx, services)
	} else if svc := findService(services, "angie"); svc != nil {
		a.registerAngie(ctx, services)
	} else {
		a.registerNginx(ctx, services)
	}

	// S.M.A.R.T. disk monitoring — always enabled, [Smart] overrides interval.
	a.registerSmart(ctx)
}

// discoverAccessLogs extracts access logs with $request_time from a DiscoverResult and returns a LogConfig.
func (a *App) discoverAccessLogs(ctx context.Context, label string, discovered *nginx.DiscoverResult) nginx.LogConfig {
	for name, format := range discovered.LogFormats {
		hasTiming := strings.Contains(format, "$request_time") || strings.Contains(format, "request_time")
		isJSON := discovered.JSONFormats[name]
		a.Print(ctx, "log_format detected", "label", label, "name", name, "timing", hasTiming, "json", isJSON)
	}

	cfg := nginx.LogConfig{
		LogFormats: make(map[string]string),
		JSONPaths:  make(map[string]bool),
	}
	seen := make(map[string]bool)
	for _, entry := range discovered.AccessLogs {
		if seen[entry.Path] {
			continue
		}
		format, ok := discovered.LogFormats[entry.FormatName]
		if !ok {
			continue
		}
		isJSON := discovered.JSONFormats[entry.FormatName]
		hasTiming := strings.Contains(format, "$request_time") || (isJSON && strings.Contains(format, "request_time"))
		if !hasTiming {
			continue
		}
		seen[entry.Path] = true
		cfg.LogPaths = append(cfg.LogPaths, entry.Path)
		cfg.LogFormats[entry.Path] = format
		if isJSON {
			cfg.JSONPaths[entry.Path] = true
		}
		if cfg.LogFormat == "" {
			cfg.LogFormat = format
		}
	}
	return cfg
}

// statusURL builds a URL from host, port and path.
// Host defaults to 127.0.0.1, port defaults to 80.
func statusURL(host string, port int, path string) string {
	if host == "" {
		host = "127.0.0.1"
	}
	if port == 0 {
		port = 80
	}
	return fmt.Sprintf("http://%s%s", net.JoinHostPort(host, strconv.Itoa(port)), path)
}

// registerLogCollector creates and registers a log collector for the given config.
func (a *App) registerLogCollector(ctx context.Context, cfg nginx.LogConfig) {
	if len(cfg.LogPaths) == 0 {
		return
	}
	logC := nginx.NewLogCollector(a.Logger, cfg)
	a.addCollector(logC)
	go logC.RunPaths(ctx, cfg.LogPaths)
}

func (a *App) registerPostgres(ctx context.Context, services []topsrv.Service) {
	if a.cfg.Postgres != nil && a.cfg.Postgres.Disabled {
		a.Print(ctx, "postgres: disabled by config")
		return
	}

	var dsn string

	if a.cfg.Postgres != nil {
		dsn = a.cfg.Postgres.DSN
	} else {
		// Auto-discovery: build DSN from discovered instance + Push token.
		svc := findService(services, "postgresql")
		if svc == nil {
			a.Print(ctx, "postgres: not found")
			return
		}
		dsn = postgres.BuildDSN(svc.Instance, a.cfg.Push.Token)
		a.Print(ctx, "postgres: found, trying auto-connect", "instance", svc.Instance)
	}

	pg, err := postgres.NewCollector(a.Logger, dsn)
	if err != nil {
		a.Error(ctx, "postgres: failed to connect", "error", err)
		return
	}

	a.addCollector(pg)
	a.closers = append(a.closers, pg)
	if a.pusher != nil {
		a.pusher.AddMetaProvider(pg)
	}
}

func (a *App) registerSmart(ctx context.Context) {
	if a.cfg.Smart != nil && a.cfg.Smart.Disabled {
		return
	}
	var interval string
	if a.cfg.Smart != nil {
		interval = a.cfg.Smart.Interval
	}
	c := smart.NewCollector(a.Logger, interval)
	a.addCollector(c)
	go c.Run(ctx)
}

func (a *App) registerNginx(ctx context.Context, services []topsrv.Service) {
	ngxCfg := a.cfg.Nginx

	// Auto-discover from nginx.conf if no explicit config or config has no AccessLogs.
	needsDiscovery := ngxCfg == nil || len(ngxCfg.AccessLogs) == 0
	if needsDiscovery { //nolint:nestif
		svc := findService(services, "nginx")
		if svc == nil {
			return
		}
		if svc.ConfigPath == "" {
			a.Print(ctx, "nginx: found but no config path — add [Nginx] section to config")
			return
		}

		discovered, err := nginx.DiscoverConfig(svc.ConfigPath)
		if err != nil {
			a.Error(ctx, "nginx: failed to parse config", "path", svc.ConfigPath, "error", err)
			return
		}

		logCfg := a.discoverAccessLogs(ctx, "nginx", discovered)

		// Preserve ExtraLabels from config when auto-discovering logs.
		if ngxCfg != nil {
			logCfg.ExtraLabels = ngxCfg.ExtraLabels
		}
		ngxCfg = &NginxConfig{
			AccessLogs: logCfg.LogPaths,
			logCfg:     logCfg,
		}

		if discovered.StubStatusPath != "" {
			ngxCfg.StubStatusURL = statusURL(discovered.StubStatusHost, discovered.StubStatusPort, discovered.StubStatusPath)
			a.Print(ctx, "nginx: auto-detected stub_status", "url", ngxCfg.StubStatusURL)
		}

		if len(discovered.SSLCertificates) > 0 {
			a.addCollector(nginx.NewSSLCollector(a.Logger, discovered.SSLCertificates))
			a.Print(ctx, "nginx: monitoring SSL certificates", "count", len(discovered.SSLCertificates))
		}

		a.Print(ctx, "nginx: auto-discovered access logs", "count", len(ngxCfg.AccessLogs), "config", svc.ConfigPath)
	} else {
		ngxCfg.logCfg = nginx.LogConfig{
			LogPaths:    ngxCfg.AccessLogs,
			LogFormat:   ngxCfg.LogFormat,
			ExtraLabels: ngxCfg.ExtraLabels,
		}
	}

	if ngxCfg.StubStatusURL != "" {
		a.addCollector(nginx.NewStubCollector(a.Logger, ngxCfg.StubStatusURL))
	}

	a.registerLogCollector(ctx, ngxCfg.logCfg)
}

func (a *App) registerAngie(ctx context.Context, services []topsrv.Service) {
	angieCfg := a.cfg.Angie

	// Auto-discover from angie.conf if no explicit config or config has no AccessLogs.
	needsDiscovery := angieCfg == nil || len(angieCfg.AccessLogs) == 0
	if needsDiscovery { //nolint:nestif
		svc := findService(services, "angie")
		if svc == nil {
			return
		}
		if svc.ConfigPath == "" {
			a.Print(ctx, "angie: found but no config path — add [Angie] section to config")
			return
		}

		discovered, err := nginx.DiscoverConfig(svc.ConfigPath)
		if err != nil {
			a.Error(ctx, "angie: failed to parse config", "path", svc.ConfigPath, "error", err)
			return
		}

		logCfg := a.discoverAccessLogs(ctx, "angie", discovered)

		// Preserve ExtraLabels and StatusURL from config when auto-discovering logs.
		var cfgStatusURL, cfgStubStatusURL string
		if angieCfg != nil {
			logCfg.ExtraLabels = angieCfg.ExtraLabels
			cfgStatusURL = angieCfg.StatusURL
			cfgStubStatusURL = angieCfg.StubStatusURL
		}
		angieCfg = &AngieConfig{
			AccessLogs:    logCfg.LogPaths,
			logCfg:        logCfg,
			StatusURL:     cfgStatusURL,
			StubStatusURL: cfgStubStatusURL,
		}

		if discovered.APIStatusPath != "" && angieCfg.StatusURL == "" {
			angieCfg.StatusURL = statusURL(discovered.APIStatusHost, discovered.APIStatusPort, discovered.APIStatusPath)
			a.Print(ctx, "angie: auto-detected API", "url", angieCfg.StatusURL)
		}
		if discovered.StubStatusPath != "" && angieCfg.StubStatusURL == "" {
			angieCfg.StubStatusURL = statusURL(discovered.StubStatusHost, discovered.StubStatusPort, discovered.StubStatusPath)
			a.Print(ctx, "angie: auto-detected stub_status", "url", angieCfg.StubStatusURL)
		}

		if len(discovered.SSLCertificates) > 0 {
			a.addCollector(nginx.NewSSLCollector(a.Logger, discovered.SSLCertificates))
			a.Print(ctx, "angie: monitoring SSL certificates", "count", len(discovered.SSLCertificates))
		}

		a.Print(ctx, "angie: auto-discovered access logs", "count", len(angieCfg.AccessLogs), "config", svc.ConfigPath)
	} else {
		angieCfg.logCfg = nginx.LogConfig{
			LogPaths:    angieCfg.AccessLogs,
			LogFormat:   angieCfg.LogFormat,
			ExtraLabels: angieCfg.ExtraLabels,
		}
	}

	// Register API collector (preferred) or stub_status fallback.
	if angieCfg.StatusURL != "" {
		a.addCollector(angie.NewAPICollector(a.Logger, angieCfg.StatusURL))
	} else if angieCfg.StubStatusURL != "" {
		a.addCollector(nginx.NewStubCollector(a.Logger, angieCfg.StubStatusURL))
	}

	a.registerLogCollector(ctx, angieCfg.logCfg)
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
	a.Print(context.Background(), "collector registered", "name", c.Name())
}
