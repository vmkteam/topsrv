package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"
	"github.com/vmkteam/topsrv/internal/topsrv/angie"
	"github.com/vmkteam/topsrv/internal/topsrv/botlog"
	"github.com/vmkteam/topsrv/internal/topsrv/nginx"
	"github.com/vmkteam/topsrv/internal/topsrv/postgres"
	"github.com/vmkteam/topsrv/internal/topsrv/smart"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/v4/host"
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
	BotLogs  *botlog.Config      `toml:"BotLogs,omitempty"`
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

	appName        string
	version        string
	cfg            Config
	srv            *http.Server
	registry       *prometheus.Registry
	pusher         *topsrv.Pusher
	closers        []io.Closer
	statusBody     []byte
	hostname       string
	scrapeDuration *prometheus.GaugeVec
	scrapePanics   *prometheus.CounterVec
	configWarnings *prometheus.CounterVec

	// Populated by registerLogCollector; tailing starts in Run() after
	// observers (e.g. botlog) have been attached.
	logCollector *nginx.LogCollector

	// Built once in registerLogCollector; consumed by registerBotLogs to wire
	// Observer's positional field-index resolution.
	extractFields []string

	// Per-format field aliases resolved from discovered log_format strings.
	// registerLogCollector picks one canonical set (warning on mismatch) and
	// registerBotLogs hands it to NewObserver.
	botlogAliases botlog.FieldAliases

	// Tracks pusher/log collector/smart/updater so Shutdown can wait for
	// their drain paths before the process exits.
	bg sync.WaitGroup
}

// shutdownTimeout caps the whole shutdown — HTTP server drain and background
// goroutine drain run in parallel under a single deadline. The botlog pusher's
// final flush relies on `shutdownTimeout ≥ botlog.shutdownDrainBudget + slack`
// (flushFinal performs one send and falls through to spool — no retry chain).
// k8s `terminationGracePeriodSeconds` should be at least this much + 5s slack.
const shutdownTimeout = 15 * time.Second

// httpShutdownTimeout caps just the net/http server's graceful shutdown so a
// stuck keep-alive can't starve the pusher's final flush of the outer budget.
const httpShutdownTimeout = 5 * time.Second

func New(appName, version string, logger embedlog.Logger, cfg Config) *App {
	body, _ := json.Marshal(map[string]string{"status": "ok", "app": appName, "version": version})
	hostname := ""
	if info, err := host.Info(); err == nil {
		hostname = info.Hostname
	}
	a := &App{
		Logger:     logger,
		appName:    appName,
		version:    version,
		cfg:        cfg,
		registry:   prometheus.NewRegistry(),
		statusBody: body,
		hostname:   hostname,
		scrapeDuration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "topsrv_collector_scrape_duration_seconds",
			Help: "Last scrape duration in seconds, by collector. Use to spot slow collectors adding overhead.",
		}, []string{"collector"}),
		scrapePanics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_collector_scrape_panics_total",
			Help: "Number of panics recovered during Collect() calls, by collector. Any non-zero rate means a bug.",
		}, []string{"collector"}),
		configWarnings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_collector_config_warnings_total",
			Help: "Operator-config warnings raised at startup. kind=high_card_label|missing_extract|truncated_extract|botlog_no_ua_field|botlog_alias_mismatch.",
		}, []string{"kind"}),
	}
	a.registry.MustRegister(a.scrapeDuration, a.scrapePanics, a.configWarnings)
	return a
}

// Run starts the HTTP server and push loop.
func (a *App) Run(ctx context.Context) error {
	a.Print(ctx, "starting", "app", a.appName, "version", a.version)

	services := topsrv.Discover(ctx, a.Logger)

	if a.cfg.Push.Endpoint != "" {
		a.pusher = topsrv.NewPusher(a.Logger, a.appName, a.version, a.cfg.Push, a.registry)
	} else {
		a.Print(ctx, "push: disabled — set [Push].Endpoint to send metrics to VictoriaMetrics")
	}

	a.registerCollectors(ctx, services)

	a.registerBotLogs(ctx)

	if a.logCollector != nil {
		a.goBackground(func() { a.logCollector.Run(ctx) })
	}

	if a.pusher != nil {
		a.goBackground(func() { a.pusher.Run(ctx) })

		if a.cfg.Update.Enabled {
			updater := topsrv.NewUpdater(a.Logger, a.appName, a.version, a.cfg.Update, a.cfg.Push)
			a.goBackground(func() { updater.Run(ctx) })
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
	overall, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if a.srv != nil {
		a.goBackground(func() {
			srvCtx, srvCancel := context.WithTimeout(overall, httpShutdownTimeout)
			defer srvCancel()
			if err := a.srv.Shutdown(srvCtx); err != nil {
				a.Error(srvCtx, "http shutdown error", "error", err)
			}
		})
	}

	done := make(chan struct{})
	go func() {
		a.bg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-overall.Done():
		a.Error(context.Background(), "shutdown: background goroutines did not finish in time", "timeout", shutdownTimeout)
	}

	for _, c := range a.closers {
		_ = c.Close()
	}
}

func (a *App) goBackground(fn func()) {
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		fn()
	}()
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

// discoverAccessLogs extracts access logs from a DiscoverResult and returns a LogConfig.
// By default, only logs whose format includes $request_time are tailed — the
// metrics collector's main reason to read them is the timing histogram.
// When [BotLogs] is enabled the filter is dropped so bot events from
// timing-less log_formats also flow through; timing histograms are then
// skipped per-line in recordLine while status counters and observers work
// on any format.
func (a *App) discoverAccessLogs(ctx context.Context, label string, discovered *nginx.DiscoverResult) nginx.LogConfig {
	needAllLogs := a.cfg.BotLogs != nil && a.cfg.BotLogs.Enabled
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
		if !needAllLogs {
			hasTiming := strings.Contains(format, "$request_time") || (isJSON && strings.Contains(format, "request_time"))
			if !hasTiming {
				continue
			}
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

// highCardLabelDenylist names nginx variables that explode Prometheus
// cardinality if used as labels on topsrv_nginx_http_requests_total. Operator
// configs that include any of these are flagged via WARN log — agent still
// starts, but the operator is on the hook for the dashboards.
var highCardLabelDenylist = []string{
	"remote_addr",
	"http_user_agent",
	"http_referer",
	"http_x_forwarded_for",
	"request_id",
	"args",
	"query_string",
}

// registerLogCollector creates and registers a log collector. Tailing is not
// started here — App.Run starts logCollector.Run after observers attach.
//
// BotLogs.RequiredFields() is merged into ExtractFields (parser reads) when
// BotLogs is enabled; ExtraLabels (Prometheus labels) is left untouched so
// observer needs can't inflate label cardinality. Operator-config warnings
// are logged via Print and tick topsrv_collector_config_warnings_total so the
// degraded state stays visible in Prometheus, not just startup stdout.
func (a *App) registerLogCollector(ctx context.Context, cfg nginx.LogConfig) {
	if len(cfg.LogPaths) == 0 {
		return
	}
	if bad := highCardLabels(cfg.ExtraLabels); len(bad) > 0 {
		a.warnConfig(ctx, "high_card_label",
			"ExtraLabels contains high-cardinality variables — Prometheus series may explode",
			"forbidden", bad, "see", "docs/metrics.md")
	}

	cfg.ExtractFields = cfg.ExtraLabels
	if a.cfg.BotLogs != nil && a.cfg.BotLogs.Enabled {
		a.botlogAliases = a.resolveBotlogAliases(ctx, cfg)
		cfg.ExtractFields = mergeUnique(cfg.ExtraLabels, botlog.RequiredFields(a.botlogAliases))
		if a.botlogAliases.UserAgent == "" {
			a.warnConfig(ctx, "botlog_no_ua_field",
				"BotLogs enabled but no tailed log_format contains http_user_agent; events will never match — check nginx/angie log_format directives, or set [BotLogs.FieldAliases].UserAgent to the custom field name",
				"log_paths", cfg.LogPaths)
		}
	}

	if dropped := capExtractFields(&cfg); len(dropped) > 0 {
		a.warnConfig(ctx, "truncated_extract",
			"ExtractFields truncated to fit ParsedLine.Extras",
			"kept", nginx.MaxExtras, "dropped", truncateList(dropped, 16))
	}
	if missing := missingFromExtract(cfg.ExtraLabels, cfg.ExtractFields); len(missing) > 0 {
		a.warnConfig(ctx, "missing_extract",
			"ExtraLabels references variables missing from ExtractFields — those label values will be empty",
			"missing", truncateList(missing, 16))
	}

	a.extractFields = cfg.ExtractFields
	logC := nginx.NewLogCollector(a.Logger, cfg)
	a.addCollector(logC)
	a.logCollector = logC
}

// warnConfig logs the warning and increments the metric for post-hoc visibility.
// Severity is Print, not Error — embedlog has no Warn level, but encoding
// severity in the message text fights log-aggregator level filters.
func (a *App) warnConfig(ctx context.Context, kind, msg string, kv ...any) {
	a.configWarnings.WithLabelValues(kind).Inc()
	a.Print(ctx, "WARN: "+msg, kv...)
}

// capExtractFields trims cfg.ExtractFields to nginx.MaxExtras and returns the
// dropped tail. The cap matches ParsedLine.Extras' fixed array size.
func capExtractFields(cfg *nginx.LogConfig) []string {
	if len(cfg.ExtractFields) <= nginx.MaxExtras {
		return nil
	}
	dropped := append([]string(nil), cfg.ExtractFields[nginx.MaxExtras:]...)
	cfg.ExtractFields = cfg.ExtractFields[:nginx.MaxExtras]
	return dropped
}

func missingFromExtract(labels, extract []string) []string {
	var missing []string
	for _, l := range labels {
		if !slices.Contains(extract, l) {
			missing = append(missing, l)
		}
	}
	return missing
}

func truncateList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), "…+more")
}

// resolveBotlogAliases inspects every log_format paired with cfg's LogPaths
// (default plus per-path overrides) and returns one canonical alias set for
// the Observer. The TOML override from BotLogs.FieldAliases wins, then the
// detected aliases, with DefaultAliases as the last-resort layer.
//
// Multi-format setups: if paths resolve to non-identical alias sets we keep
// the first path's resolution and emit a config warning — the v2 plan is
// per-path Observer wiring once an operator hits this in production.
func (a *App) resolveBotlogAliases(ctx context.Context, cfg nginx.LogConfig) botlog.FieldAliases {
	override := botlog.FieldAliases{}
	if a.cfg.BotLogs != nil {
		override = a.cfg.BotLogs.FieldAliases
	}

	formatFor := func(p string) (string, bool) {
		if f, ok := cfg.LogFormats[p]; ok {
			return f, cfg.JSONPaths[p]
		}
		return cfg.LogFormat, false
	}

	// Memoise per (format, isJSON) — N paths sharing one log_format incur
	// one DetectAliases call instead of N.
	type formatKey struct {
		format string
		isJSON bool
	}
	detectCache := make(map[formatKey]botlog.FieldAliases)

	var canonical, canonicalDetected botlog.FieldAliases
	var canonicalPath string
	mismatched := make([]string, 0)
	for _, p := range cfg.LogPaths {
		format, isJSON := formatFor(p)
		key := formatKey{format, isJSON}
		detected, ok := detectCache[key]
		if !ok {
			detected = botlog.DetectAliases(format, isJSON)
			detectCache[key] = detected
		}
		resolved := override.WithFallback(detected).WithFallback(botlog.DefaultAliases())
		if canonicalPath == "" {
			canonical = resolved
			canonicalDetected = detected
			canonicalPath = p
			continue
		}
		if resolved != canonical {
			mismatched = append(mismatched, p)
		}
	}
	if len(mismatched) > 0 {
		a.warnConfig(ctx, "botlog_alias_mismatch",
			"log_formats across tailed paths resolve to different botlog aliases; using first path's resolution",
			"canonical_path", canonicalPath, "mismatched_paths", truncateList(mismatched, 8))
	}
	if canonicalPath != "" {
		a.Print(ctx, "botlog: resolved field aliases",
			"aliases", canonical.String(),
			"sources", aliasSources(override, canonicalDetected),
			"canonical_path", canonicalPath)
	}
	return canonical
}

// aliasSources renders per-field provenance: "override" if the operator set
// the alias via [BotLogs.FieldAliases], "detected" if it came from
// log_format inspection, "default" if neither matched and DefaultAliases
// supplied the value. Mirrors FieldAliases.String() shape so log readers can
// align the two lines.
func aliasSources(override, detected botlog.FieldAliases) string {
	src := func(o, d string) string {
		switch {
		case o != "":
			return "override"
		case d != "":
			return "detected"
		default:
			return "default"
		}
	}
	return fmt.Sprintf("ua=%s host=%s server=%s remote=%s referer=%s",
		src(override.UserAgent, detected.UserAgent),
		src(override.Host, detected.Host),
		src(override.ServerName, detected.ServerName),
		src(override.RemoteAddr, detected.RemoteAddr),
		src(override.Referer, detected.Referer),
	)
}

// highCardLabels returns the intersection of labels with the denylist.
func highCardLabels(labels []string) []string {
	var bad []string
	for _, l := range labels {
		if slices.Contains(highCardLabelDenylist, l) {
			bad = append(bad, l)
		}
	}
	return bad
}

// mergeUnique returns base ++ (extras \ base), preserving order. Operator's
// labels stay at the front so their positions in ParsedLine.Extras are stable
// across config reloads.
func mergeUnique(base, extras []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extras))
	out := make([]string, 0, len(base)+len(extras))
	for _, v := range base {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range extras {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
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

	// NewCollector is lazy — pool is created on first Collect, so a temporarily-unreachable
	// PG (e.g. boot-time ordering) no longer disables monitoring until restart.
	pg, err := postgres.NewCollector(a.Logger, dsn)
	if err != nil {
		a.Error(ctx, "postgres: invalid DSN", "error", err)
		return
	}

	a.addCollector(pg)
	a.closers = append(a.closers, pg)
	if a.pusher != nil {
		a.pusher.AddMetaProvider(pg)
	}
}

// registerBotLogs no-ops when [BotLogs] is disabled or no nginx access logs
// were discovered. Otherwise it validates the config, builds the Pusher,
// attaches the Observer to the access-log collector before tailing starts, and
// launches the pusher goroutine.
func (a *App) registerBotLogs(ctx context.Context) {
	if a.cfg.BotLogs == nil || !a.cfg.BotLogs.Enabled {
		return
	}
	if err := a.cfg.BotLogs.Validate(a.cfg.Push); err != nil {
		a.Error(ctx, "botlog: invalid config — disabled", "error", err)
		return
	}
	if a.logCollector == nil {
		a.Print(ctx, "botlog: no nginx access logs discovered — disabled")
		return
	}
	bp := botlog.NewPusher(a.Logger, a.appName, a.version, *a.cfg.BotLogs, a.registry)
	obs := botlog.NewObserver(bp, *a.cfg.BotLogs, a.hostname, a.extractFields, a.botlogAliases)
	a.logCollector.AddObserver(obs)
	a.goBackground(func() { bp.Run(ctx) })
	a.Print(ctx, "botlog: observer attached", "endpoint", a.cfg.BotLogs.Endpoint, "spool", a.cfg.BotLogs.SpoolDir)
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
	a.goBackground(func() { c.Run(ctx) })
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
	a.registry.MustRegister(&instrumentedCollector{
		inner:    c,
		logger:   a.Logger,
		duration: a.scrapeDuration.WithLabelValues(c.Name()),
		panics:   a.scrapePanics.WithLabelValues(c.Name()),
	})
	a.Print(context.Background(), "collector registered", "name", c.Name())
}

// instrumentedCollector wraps a topsrv.Collector to record its scrape duration
// and recover from panics. Panics are logged and counted but not re-raised, so
// a bug in one collector can't break the whole /metrics response.
type instrumentedCollector struct {
	inner    topsrv.Collector
	logger   embedlog.Logger
	duration prometheus.Gauge
	panics   prometheus.Counter
}

func (ic *instrumentedCollector) Describe(ch chan<- *prometheus.Desc) {
	ic.inner.Describe(ch)
}

func (ic *instrumentedCollector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	defer func() {
		ic.duration.Set(time.Since(start).Seconds())
		if r := recover(); r != nil {
			ic.panics.Inc()
			ic.logger.Error(context.Background(), "collector panic recovered", "collector", ic.inner.Name(), "panic", r)
		}
	}()
	ic.inner.Collect(ch)
}
