package smart

import (
	"cmp"
	"math"
	"slices"
)

// defaultSectorSize is the ATA logical sector size, and the value smartmontools,
// node_exporter and scrutiny assume for every drive when scaling LBA counters.
const defaultSectorSize = 512

// hostWriteAttr is what host-write resolution needs from one ATA SMART
// attribute. The three fields are copied out of the SMART library's type rather
// than used through it because this project builds with CGO_ENABLED=0
// (Makefile, and goreleaser for static binaries), and under that setting
// anatol/smart.go does not compile on darwin — its nvme_darwin.go needs cgo.
// Importing the library from a file without a build tag would make the whole
// package, and every test in it, unbuildable on the dev machine where
// `make fmt lint test` is the pre-commit gate.
type hostWriteAttr struct {
	id       uint8
	name     string
	valueRaw uint64
}

// writeUnit describes the byte size of one raw-value unit of an ATA host-write
// attribute. Vendors disagree: some count logical sectors, some GiB, some
// 32 MiB chunks, and the smartmontools device database embedded in the SMART
// library is the only thing that tells them apart — by attribute name, not by
// id. Id-based matching is not an option: the default database names 225
// Load_Cycle_Count, an HDD head-parking counter that a rule keyed on "225 is
// host writes" would publish as tens of terabytes.
type writeUnit struct {
	bytes     uint64 // size of one unit; ignored when perSector is set
	perSector bool   // one unit is one logical sector, size read from sysfs
}

// hostWriteAttrs maps attribute names to their unit. Names come from the
// smartmontools database embedded in anatol/smart.go, so they must match it
// verbatim. NAND-side counters (Total_NAND_Written, NAND_GB_Written_TLC) are
// deliberately absent: they measure flash writes after amplification, not host
// writes, and mixing them into one metric would make the series incomparable
// across a fleet.
var hostWriteAttrs = map[string]writeUnit{
	"Total_LBAs_Written":     {perSector: true},
	"Sectors_Written_to_SSD": {perSector: true},
	"Host_Writes_GiB":        {bytes: 1 << 30},
	"Total_Writes_GiB":       {bytes: 1 << 30},
	"Lifetime_Writes_GiB":    {bytes: 1 << 30},
	"Host_Writes_32MiB":      {bytes: 32 << 20},
	"Host_Writes_MiB":        {bytes: 1 << 20},
}

// hostBytesWritten returns total host bytes written, resolved from the
// lowest-numbered attribute of documented unit on the SMART page. sectorSize 0
// means the ATA default. ok is false when the drive exposes no such attribute —
// the right answer for an HDD, which has no host-write counter at all, and
// better than a series in unknown units, off by three orders of magnitude
// between models.
//
// The id order is load-bearing, not cosmetic: the page is a Go map, and the
// Intel DC preset names both 225 and 241 Host_Writes_32MiB, so an unordered
// scan would alternate between the two raw values from scrape to scrape once
// they diverge. Summing them is wrong for the same reason — it is one counter
// the firmware exposes twice. Sorts attrs in place; the caller builds the slice
// fresh per scrape (pageWriteAttrs).
func hostBytesWritten(attrs []hostWriteAttr, sectorSize uint64) (uint64, bool) {
	if sectorSize == 0 {
		sectorSize = defaultSectorSize
	}
	slices.SortFunc(attrs, func(a, b hostWriteAttr) int { return cmp.Compare(a.id, b.id) })

	for _, attr := range attrs {
		unit, known := hostWriteAttrs[attr.name]
		// A zero raw value means the drive does not fill this attribute, not
		// that nothing was ever written — keep looking instead of reporting 0.
		if !known || attr.valueRaw == 0 {
			continue
		}

		size := unit.bytes
		if unit.perSector {
			size = sectorSize
		}
		// The raw value is 48 bits of vendor-filled data. Scaled by a GiB unit
		// a garbage reading wraps uint64 into a small number, and a counter
		// that went backwards is worse downstream than a missing one.
		if attr.valueRaw > math.MaxUint64/size {
			continue
		}
		return attr.valueRaw * size, true
	}
	return 0, false
}
