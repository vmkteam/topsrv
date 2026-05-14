//go:build !linux

package packages

import "context"

// scan is a no-op on non-Linux platforms. dpkg/rpm/apk databases live under
// /var/lib/<manager>/ on Linux only.
func (c *Collector) scan(_ context.Context) {}
