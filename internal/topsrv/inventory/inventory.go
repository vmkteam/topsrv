// Package inventory holds the envelope shared by every /v1/inventory snapshot
// kind and the host facts that go with it.
package inventory

import "time"

// Manager values for HostMeta.PackageManager, labels and discovery dispatch.
const (
	ManagerDpkg = "dpkg"
	ManagerRpm  = "rpm"
	ManagerApk  = "apk"
)

// Payload — body shape for POST /v1/inventory. The kind discriminator routes
// snapshots on the backend. Host-level facts (osId, kernelRelease, ...) live
// in `host`, not in every data row — keeps payload small.
type Payload struct {
	Kind      string    `json:"kind"`
	ScannedAt time.Time `json:"scannedAt"`
	// AgentVersion is the agent build that collected the snapshot. The pusher
	// sets it before the body is sent or spooled, so a snapshot resent after
	// an update still names the version that built it.
	AgentVersion string   `json:"agentVersion,omitempty"`
	Host         HostMeta `json:"host"`
	Data         any      `json:"data"`
}

// HostMeta — required upstream by Vulners audit (osId+osVersionId+kernelRelease).
// kernelRelease is critical: Vulners' agent filters kernel-*/linux-image-* not
// matching `uname -r` to avoid false positives on inactive kernels.
// PackageManager is required by the inventory endpoint for every kind.
type HostMeta struct {
	OsID              string   `json:"osId"`
	OsVersionID       string   `json:"osVersionId"`
	OsVersionCodename string   `json:"osVersionCodename,omitempty"`
	OsIDLike          []string `json:"osIdLike,omitempty"`
	OsPrettyName      string   `json:"osPrettyName,omitempty"`
	KernelRelease     string   `json:"kernelRelease"`
	KernelArch        string   `json:"kernelArch,omitempty"`
	PackageManager    string   `json:"packageManager"`
	// RebootRequired — a kernel image newer than the running one is installed;
	// the update takes effect only after a reboot. Per manager snapshot.
	RebootRequired bool `json:"rebootRequired,omitempty"`
}
