package smart

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// attrs is a SMART page in test shorthand: attribute id → name and raw value.
// page() flattens it the way the collector does (pageWriteAttrs), i.e. into an
// unordered slice — the real page is a Go map, so every test below exercises
// the id sort rather than assuming a convenient order.
type attrs map[uint8]struct {
	name string
	raw  uint64
}

func (a attrs) page() []hostWriteAttr {
	out := make([]hostWriteAttr, 0, len(a))
	for id, v := range a {
		out = append(out, hostWriteAttr{id: id, name: v.name, valueRaw: v.raw})
	}
	return out
}

// The metric is named bytes but the library hands out "data units (LBA)".
// Publishing the raw value understated every SATA drive by 512x. The value is
// taken from a production SATA SSD whose 246 TB cross-checks against its
// Wear_Leveling_Count.
func TestHostBytesWritten_LBAs(t *testing.T) {
	got, ok := hostBytesWritten(attrs{241: {"Total_LBAs_Written", 480_996_991_518}}.page(), 512)
	assert.True(t, ok)
	assert.Equal(t, uint64(246_270_459_657_216), got)
}

// Vendor presets rename the attribute and change its unit with it. Before the
// unit table most SATA SSDs of a mixed fleet matched nothing and got no series
// at all.
func TestHostBytesWritten_VendorUnits(t *testing.T) {
	cases := []struct {
		name string
		id   uint8
		raw  uint64
		want uint64
	}{
		{"Host_Writes_GiB", 241, 59988, 64_411_624_538_112}, // WD SSD, ~64.4 TB
		{"Lifetime_Writes_GiB", 241, 1024, 1024 << 30},      // SandForce
		{"Total_Writes_GiB", 241, 10, 10 << 30},
		{"Host_Writes_32MiB", 225, 3_000_000, 3_000_000 * (32 << 20)}, // Intel DC
		{"Host_Writes_MiB", 175, 2048, 2048 << 20},
		{"Sectors_Written_to_SSD", 235, 1_000_000, 512_000_000}, // ATP
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := hostBytesWritten(attrs{tc.id: {tc.name, tc.raw}}.page(), 512)
			assert.True(t, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The Intel DC preset names both 225 and 241 Host_Writes_32MiB. The page comes
// out of a Go map, so without the id ordering the metric would flip between the
// two raw values from scrape to scrape. The repeat is the point of the test.
func TestHostBytesWritten_IntelDuplicateAttrs(t *testing.T) {
	page := attrs{
		225: {"Host_Writes_32MiB", 3_000_000},
		241: {"Host_Writes_32MiB", 2_999_100},
	}
	for range 100 {
		got, ok := hostBytesWritten(page.page(), 512)
		assert.True(t, ok)
		assert.Equal(t, uint64(3_000_000)*(32<<20), got, "lowest attribute id must win, every time")
	}
}

// NAND counters measure flash writes after amplification. Substituting one for
// host writes would inflate the metric by the drive's WAF, silently and by a
// different factor per model.
func TestHostBytesWritten_UnknownAttrs(t *testing.T) {
	_, ok := hostBytesWritten(attrs{
		233: {"NAND_GB_Written_TLC", 654_321},
		243: {"Total_NAND_Written", 123_456},
	}.page(), 512)
	assert.False(t, ok, "NAND-side counters must not stand in for host writes")
}

// Mechanical drives carry no host-write counter, so no series is the correct
// answer for every HDD. This is also the guard against matching by
// id: the default database names 225 Load_Cycle_Count, and a head-parking count
// scaled by 32 MiB would read as tens of terabytes written.
func TestHostBytesWritten_HDD(t *testing.T) {
	_, ok := hostBytesWritten(attrs{
		5:   {"Reallocated_Sector_Ct", 0},
		9:   {"Power_On_Hours", 57_000},
		225: {"Load_Cycle_Count", 1_200_000},
	}.page(), 512)
	assert.False(t, ok)
}

// Total_LBAs_Written counts logical sectors, so a 4Kn drive wrote 8x what the
// hardcoded 512 of every other SMART tool would report. A zero sector size is
// the "sysfs said nothing" case and must fall back to the ATA default, never
// scale the counter to zero.
func TestHostBytesWritten_SectorSize(t *testing.T) {
	page := attrs{241: {"Total_LBAs_Written", 480_996_991_518}}

	got4K, ok := hostBytesWritten(page.page(), 4096)
	assert.True(t, ok)
	assert.Equal(t, uint64(246_270_459_657_216)*8, got4K)

	gotDefault, ok := hostBytesWritten(page.page(), 0)
	assert.True(t, ok)
	assert.Equal(t, uint64(246_270_459_657_216), gotDefault)
}

// A zero raw value is "this drive does not fill the attribute", not "nothing
// was ever written" — fall through to the next candidate instead of emitting 0.
func TestHostBytesWritten_ZeroFallsThrough(t *testing.T) {
	got, ok := hostBytesWritten(attrs{
		241: {"Host_Writes_GiB", 0},
		246: {"Total_LBAs_Written", 1_000_000},
	}.page(), 512)
	assert.True(t, ok)
	assert.Equal(t, uint64(512_000_000), got)
}

// A wrapped product reads as a counter that went backwards, which is worse
// downstream than a gap in the series.
func TestHostBytesWritten_OverflowRejected(t *testing.T) {
	_, ok := hostBytesWritten(attrs{
		241: {"Host_Writes_GiB", math.MaxUint64/(1<<30) + 1},
	}.page(), 512)
	assert.False(t, ok)
}
