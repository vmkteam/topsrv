//go:build linux

package security

import "golang.org/x/sys/unix"

// timeSyncReader returns the adjtimex reader on Linux.
func timeSyncReader() func() (*timeSync, error) { return readTimeSync }

// readTimeSync reads the clock state with adjtimex in read-only mode
// (Modes=0), which needs no privileges. In a container it shows the host.
func readTimeSync() (*timeSync, error) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return nil, err
	}
	offset := tx.Offset
	if tx.Status&unix.STA_NANO != 0 {
		offset /= 1000
	}
	return &timeSync{
		Unsync:     tx.Status&unix.STA_UNSYNC != 0,
		ClockErr:   state == unix.TIME_ERROR,
		MaxErrorUs: tx.Maxerror,
		OffsetUs:   offset,
	}, nil
}
