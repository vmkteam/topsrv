//go:build !linux

package security

// timeSyncReader: adjtimex exists on Linux only.
func timeSyncReader() func() (*timeSync, error) { return nil }
