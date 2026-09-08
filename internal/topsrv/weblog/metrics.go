package weblog

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the observer-side counters. Delivery has its own set under the
// same prefix, registered by the shipper.
//
// filtered_total earns its place three times over: a zero count on a configured
// filter means the rule never matches (usually written against the normalized
// path instead of the raw one); its sum with the events the sink accepted is
// what the stream would cost unfiltered, which is how the price of widening it
// gets estimated without widening it; and it is a partial stand-in for the
// "client never fetches assets" signal that disappears along with the filtered
// lines. Partial because the counter is per host, while the signal is per
// client — the full version is a per-address counter, and it belongs on the
// receiving side.
//
// The four filter counters are resolved once and reached as fields: every call
// site knows at compile time which one it wants, and the label lookup is not
// worth paying on a path that runs per line.
type Metrics struct {
	// Filter reasons, bounded on purpose — an unbounded reason set would do to
	// our own metrics what an unfiltered URI does to a low-cardinality column.
	FilteredPath      prometheus.Counter
	FilteredUpstream  prometheus.Counter
	FilteredProxyHost prometheus.Counter
	FilteredPrefix    prometheus.Counter

	matched *prometheus.CounterVec

	// Bot traffic arrives in runs from one family, so a one-entry memo answers
	// most calls without the variadic slice WithLabelValues allocates.
	lastFamily  string
	lastCounter prometheus.Counter
}

// NewMetrics registers the observer counters. tailed is the number of access
// logs that survived the startup format checks — fixed for the process
// lifetime, which is why it is a plain gauge set once rather than a callback.
func NewMetrics(reg prometheus.Registerer, tailed int) *Metrics {
	filtered := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "topsrv_weblog_filtered_total",
		Help: "Web-log lines rejected before an event was built, by reason.",
	}, []string{"reason"})

	m := &Metrics{
		FilteredPath:      filtered.WithLabelValues("path"),
		FilteredUpstream:  filtered.WithLabelValues("upstream"),
		FilteredProxyHost: filtered.WithLabelValues("proxy_host"),
		FilteredPrefix:    filtered.WithLabelValues("prefix"),
		matched: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "topsrv_weblog_match_total",
			Help: "Web-log lines whose user agent matched the bot list, by family. A signal, not a filter.",
		}, []string{"family"}),
	}

	tailedPaths := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "topsrv_weblog_tailed_paths",
		Help: "Access logs actually tailed by the web-log stream after format checks.",
	})
	tailedPaths.Set(float64(tailed))

	reg.MustRegister(filtered, m.matched, tailedPaths)
	return m
}

// Matched counts one line whose UA matched a known bot family.
func (m *Metrics) Matched(family string) {
	if family != m.lastFamily {
		m.lastFamily, m.lastCounter = family, m.matched.WithLabelValues(family)
	}
	m.lastCounter.Inc()
}
