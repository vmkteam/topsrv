package topsrv

import "github.com/prometheus/client_golang/prometheus"

// Collector gathers metrics from a single source.
// Implements prometheus.Collector — metrics are collected on scrape/gather.
type Collector interface {
	prometheus.Collector
	Name() string
}

// QueryMetaProvider returns query metadata for push to gatesrv.
type QueryMetaProvider interface {
	QueryMeta() []QueryMeta
}

// Service is a discovered service on the host.
type Service struct {
	Type       string // "postgresql", "nginx", "angie", "redis", "php-fpm"
	Instance   string // "127.0.0.1:5432"
	Version    string
	ConfigPath string
	Extra      map[string]any // access_logs, databases, etc.
}
