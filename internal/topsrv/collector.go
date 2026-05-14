package topsrv

import (
	"github.com/vmkteam/topsrv/internal/topsrv/packages"
	"github.com/vmkteam/topsrv/internal/topsrv/postgres"

	"github.com/prometheus/client_golang/prometheus"
)

// Collector gathers metrics from a single source.
// Implements prometheus.Collector — metrics are collected on scrape/gather.
type Collector interface {
	prometheus.Collector
	Name() string
}

// QueryMetaProvider returns query metadata for push to gatesrv /v1/meta.
type QueryMetaProvider interface {
	QueryMeta() []postgres.QueryMeta
}

// InventoryProvider returns inventory snapshots for push to gatesrv
// /v1/inventory. Each payload carries its own `kind` discriminator
// (packages, repos, packageHistory, ...). Returns nil/empty when there's
// nothing fresh to push — pusher won't send empty payloads.
//
// One-shot semantics: provider should drain its buffer after Inventory()
// is called so each snapshot is sent at most once. The optional
// InventoryAckReceiver mixin lets the provider learn which sends actually
// succeeded so it can re-queue on failure.
type InventoryProvider interface {
	Inventory() []packages.Payload
}

// InventoryAckReceiver is optionally implemented by an InventoryProvider to
// observe successful pushes. The pusher type-asserts and calls when available
// — providers that don't need ack tracking can skip it.
type InventoryAckReceiver interface {
	OnInventoryPushed(kind string)
}

// Service is a discovered service on the host.
type Service struct {
	Type       string // "postgresql", "nginx", "angie", "redis", "php-fpm"
	Instance   string // "127.0.0.1:5432"
	Version    string
	ConfigPath string
	Extra      map[string]any // access_logs, databases, etc.
}
