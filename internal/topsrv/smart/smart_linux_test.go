//go:build linux

package smart

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A device that vanished between discovery and the sysfs read must not scale
// host writes by zero; 512 is the ATA default and what every other SMART tool
// assumes unconditionally.
func TestLogicalSectorSize_Fallback(t *testing.T) {
	assert.Equal(t, uint64(defaultSectorSize), logicalSectorSize("no-such-device"))
}
