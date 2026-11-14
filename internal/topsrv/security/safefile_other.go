//go:build !unix

package security

// Off unix the collector reports unsupported_platform; the flags only keep
// the package building.
const (
	openFlags = 0
	oNoFollow = 0
)
