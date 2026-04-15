//go:build !linux

package smart

// scan is a no-op on non-Linux platforms.
// S.M.A.R.T. monitoring requires direct ioctl access to block devices.
func (c *Collector) scan() {}
