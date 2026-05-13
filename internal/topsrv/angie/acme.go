package angie

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

var _ topsrv.Collector = (*ACMECollector)(nil)

// ACMEClient mirrors one entry of /status/http/acme_clients/ (angie 1.5+).
// state/certificate are operator-facing enums whose set evolves across
// releases — we surface them as Prometheus labels instead of mapping to
// numbers. "details" is a free-form sentence intended for humans; not
// useful as a label (high cardinality, churns with translations) so we
// don't decode it. next_run is int64 because we ask for date=epoch.
type ACMEClient struct {
	State       string `json:"state"`
	Certificate string `json:"certificate"`
	NextRun     int64  `json:"next_run"`
}

// ACMECollector polls angie's per-client ACME status so dashboards can see
// when a cert is renewing / failed / due for next attempt without reading
// the PEM off disk (which only tells you NotAfter, not "renewal blocked").
type ACMECollector struct {
	embedlog.Logger

	url    string
	client *http.Client

	state   *prometheus.Desc
	nextRun *prometheus.Desc
}

// NewACMECollector extends APICollector's statusURL with /http/acme_clients/?date=epoch.
// date=epoch turns next_run into a plain Unix int so we skip ISO 8601 parsing.
func NewACMECollector(logger embedlog.Logger, statusURL string) (*ACMECollector, error) {
	u, err := url.Parse(statusURL)
	if err != nil {
		return nil, err
	}
	const suffix = "/http/acme_clients/"
	base := strings.TrimSuffix(u.Path, "/")
	if !strings.HasSuffix(base, strings.TrimSuffix(suffix, "/")) {
		base += suffix
	} else {
		base += "/"
	}
	u.Path = base
	u.RawQuery = "date=epoch"
	return &ACMECollector{
		Logger: logger,
		url:    u.String(),
		client: &http.Client{Timeout: 5 * time.Second},
		state: prometheus.NewDesc(
			"topsrv_angie_acme_state",
			"ACME client state (value=1 per name/state/certificate tuple).",
			[]string{"name", "state", "certificate"}, nil,
		),
		nextRun: prometheus.NewDesc(
			"topsrv_angie_acme_next_run_seconds",
			"Unix timestamp of next ACME action per client.",
			[]string{"name"}, nil,
		),
	}, nil
}

func (c *ACMECollector) Name() string { return "angie-acme" }

func (c *ACMECollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.state
	ch <- c.nextRun
}

func (c *ACMECollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.Error(ctx, "angie-acme: request failed", "error", err)
		return
	}
	defer resp.Body.Close()

	// 404 means acme_client isn't configured on this host — silently skip
	// so we don't spam logs every scrape. Other non-200 status are real
	// problems worth surfacing.
	if resp.StatusCode == http.StatusNotFound {
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.Error(ctx, "angie-acme: API returned error status", "status", resp.StatusCode)
		return
	}

	var clients map[string]ACMEClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		c.Error(ctx, "angie-acme: failed to decode response", "error", err)
		return
	}

	for name, cl := range clients {
		ch <- prometheus.MustNewConstMetric(c.state, prometheus.GaugeValue, 1, name, cl.State, cl.Certificate)
		// next_run is omitted by angie when state ∈ {disabled, requesting} —
		// it decodes as 0; skip emitting so dashboards see "no scheduled action".
		if cl.NextRun > 0 {
			ch <- prometheus.MustNewConstMetric(c.nextRun, prometheus.GaugeValue, float64(cl.NextRun), name)
		}
	}
}
