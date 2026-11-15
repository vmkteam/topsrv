package packages

// Status values for Package.Status. dpkg distinguishes installed vs held;
// rpm and apk collapse to a generic "installed".
const (
	StatusInstalled     = "install ok installed"
	StatusHoldInstalled = "hold ok installed"
	StatusGeneric       = "installed"
)

// Snapshot is the data shape for kind="packages".
type Snapshot struct {
	Manager  string    `json:"manager"`
	Packages []Package `json:"packages"`
	// RebootRequired and RebootRequiredPackages are shipped in HostMeta, not
	// in data.
	RebootRequired         bool     `json:"-"`
	RebootRequiredPackages []string `json:"-"`
}

// Package — security-oriented inventory entry. Field grouping mirrors the
// MUST/SHOULD/NICE classification from the Vulners + Syft/Trivy analysis;
// see docs/packages-collector-implementation.md "Security data model".
type Package struct {
	// MUST — Vulners audit requires these
	Name    string `json:"name"`
	Version string `json:"version"` // dpkg: includes epoch prefix ("1:6.7p1-5+deb8u2")
	Release string `json:"release,omitempty"`
	Epoch   *int   `json:"epoch,omitempty"` // rpm only; nil = absent
	Arch    string `json:"arch,omitempty"`
	Status  string `json:"status,omitempty"`

	// SHOULD — supply-chain, accuracy, drift
	SourceName      string `json:"sourceName,omitempty"`
	SourceVersion   string `json:"sourceVersion,omitempty"`
	ModularityLabel string `json:"modularityLabel,omitempty"` // rpm RHEL 8+
	Vendor          string `json:"vendor,omitempty"`
	GpgKeyID        string `json:"gpgKeyId,omitempty"`
	SigDigest       string `json:"sigDigest,omitempty"`
	SigAlgorithm    string `json:"sigAlgorithm,omitempty"`
	AutoInstalled   bool   `json:"autoInstalled,omitempty"`
	RepoOrigin      string `json:"repoOrigin,omitempty"`
	IsActiveKernel  bool   `json:"isActiveKernel,omitempty"`
	IsOldKernel     bool   `json:"isOldKernel,omitempty"`

	// NICE — SBOM, forensics
	InstallTime   int64    `json:"installTime,omitempty"`
	InstalledSize int64    `json:"installedSize,omitempty"`
	Licenses      []string `json:"licenses,omitempty"`
	Section       string   `json:"section,omitempty"`
	Priority      string   `json:"priority,omitempty"`
	Homepage      string   `json:"homepage,omitempty"`
	GitCommit     string   `json:"gitCommit,omitempty"`
}
