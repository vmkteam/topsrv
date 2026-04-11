package nginx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

var _ topsrv.Collector = (*StubCollector)(nil)

// StubCollector collects metrics from the nginx stub_status endpoint.
type StubCollector struct {
	embedlog.Logger

	url    string
	client *http.Client

	up          *prometheus.Desc
	connections *prometheus.Desc
	accepted    *prometheus.Desc
	handled     *prometheus.Desc
	requests    *prometheus.Desc
}

func NewStubCollector(logger embedlog.Logger, stubStatusURL string) *StubCollector {
	return &StubCollector{
		Logger: logger,
		url:    stubStatusURL,
		client: &http.Client{Timeout: 5 * time.Second},

		up:          prometheus.NewDesc("topsrv_nginx_up", "Nginx is reachable (1=yes, 0=no).", nil, nil),
		connections: prometheus.NewDesc("topsrv_nginx_connections", "Nginx connections by state.", []string{"state"}, nil),
		accepted:    prometheus.NewDesc("topsrv_nginx_connections_accepted_total", "Total accepted connections.", nil, nil),
		handled:     prometheus.NewDesc("topsrv_nginx_connections_handled_total", "Total handled connections.", nil, nil),
		requests:    prometheus.NewDesc("topsrv_nginx_requests_total", "Total HTTP requests.", nil, nil),
	}
}

func (c *StubCollector) Name() string { return "nginx" }

func (c *StubCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.connections
	ch <- c.accepted
	ch <- c.handled
	ch <- c.requests
}

func (c *StubCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}

	resp, err := c.client.Do(req)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}

	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)
	c.parseStubStatus(string(body), ch)
}

func (c *StubCollector) parseStubStatus(body string, ch chan<- prometheus.Metric) {
	var active, accepted, handled, requests int64
	var reading, writing, waiting int64

	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 4 {
		return
	}

	_, _ = fmt.Sscanf(lines[0], "Active connections: %d", &active)
	_, _ = fmt.Sscanf(strings.TrimSpace(lines[2]), "%d %d %d", &accepted, &handled, &requests)
	_, _ = fmt.Sscanf(lines[3], "Reading: %d Writing: %d Waiting: %d", &reading, &writing, &waiting)

	ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(active), "active")
	ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(reading), "reading")
	ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(writing), "writing")
	ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(waiting), "waiting")
	ch <- prometheus.MustNewConstMetric(c.accepted, prometheus.CounterValue, float64(accepted))
	ch <- prometheus.MustNewConstMetric(c.handled, prometheus.CounterValue, float64(handled))
	ch <- prometheus.MustNewConstMetric(c.requests, prometheus.CounterValue, float64(requests))
}
