package botlog

import (
	"github.com/vmkteam/topsrv/internal/topsrv/shipper"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

// Pusher ships bot-log events. Delivery — batching, retry, spool, trim — lives
// in shipper and is shared with the web-log stream; what stays here is the one
// measurement that is about bots rather than about shipping.
type Pusher struct {
	*shipper.Pusher

	matchTotal *prometheus.CounterVec // family
}

// NewPusher wires delivery with the bot-log metric names. Those names are
// load-bearing for existing dashboards, so they stay byte-for-byte as they were
// before delivery moved out of this package.
func NewPusher(logger embedlog.Logger, appName, version string, cfg Config, reg prometheus.Registerer) *Pusher {
	p := &Pusher{
		Pusher: shipper.NewPusher(logger, appName, version, shipper.Options{
			MetricPrefix:  "topsrv_botlog",
			MetricSubject: "Bot-log",
			Endpoint:      cfg.Endpoint,
			Token:         cfg.Token,
			BatchSize:     cfg.BatchSize,
			BatchInterval: cfg.ParsedBatchInterval(),
			SpoolDir:      cfg.SpoolDir,
			MaxSpoolMB:    cfg.MaxSpoolMB,
		}, reg),
		matchTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_botlog_match_total",
			Help: "Bot-log UA matches by family — incremented as observer sees a line.",
		}, []string{"family"}),
	}
	reg.MustRegister(p.matchTotal)
	return p
}

// RecordMatch ticks topsrv_botlog_match_total{family=...}. Called by the
// observer once per UA match. Keeps the CounterVec encapsulated.
func (p *Pusher) RecordMatch(family string) {
	p.matchTotal.WithLabelValues(family).Inc()
}
