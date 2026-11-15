// Package security collects security facts about the host and ships them as
// a kind="security" snapshot to /v1/inventory. The agent reports facts only:
// rules, scores and role profiles are computed by the backend.
package security

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// valueUnknown is the enum value for a fact that could not be read.
const valueUnknown = "unknown"

// valueInvalid replaces a token from a file that does not look like one: an
// odd value is not sent as it is.
const valueInvalid = "invalid"

// checked returns v when valid accepts it, valueInvalid otherwise: the text
// of a configuration line is never sent, only a value the tool accepts.
func checked(v *string, valid func(string) bool) *string {
	if v == nil || valid(*v) {
		return v
	}
	s := valueInvalid
	return &s
}

// Kind is the /v1/inventory discriminator of the security snapshot.
const Kind = "security"

// SchemaVersion of Data. Any incompatible change to the format bumps it, and
// the backend accepts both versions for a while.
const SchemaVersion = 1

// Status says how complete a section is. unknown is never a pass.
type Status string

const (
	StatusOK      Status = "ok"      // collected in full
	StatusPartial Status = "partial" // some sources unavailable, see Gaps
	StatusUnknown Status = "unknown" // nothing collected, see Reason
	StatusNA      Status = "na"      // the component is absent on this host
)

// Reason explains an unknown section or a gap.
type Reason string

const (
	ReasonPermissionDenied    Reason = "permission_denied"
	ReasonNotFound            Reason = "not_found"
	ReasonParseError          Reason = "parse_error" // read, but not understood
	ReasonNotRegular          Reason = "not_regular" // a FIFO, device or directory where a file should be, or swapped while opened
	ReasonIOError             Reason = "io_error"    // any other read failure (EIO, ...)
	ReasonTimeout             Reason = "timeout"
	ReasonContainerEnv        Reason = "container_env"
	ReasonBudgetExceeded      Reason = "budget_exceeded"
	ReasonRemoteFSSkipped     Reason = "remote_fs_skipped"
	ReasonUnsupportedPlatform Reason = "unsupported_platform"
	ReasonDumpInconsistent    Reason = "dump_inconsistent"
)

// Gap is one source a partial section could not read. Path never carries
// file content.
type Gap struct {
	Path   string `json:"path"`
	Reason Reason `json:"reason"`
}

// Section is one section of the snapshot.
type Section struct {
	Status     Status `json:"status"`
	Reason     Reason `json:"reason,omitempty"`
	DurationMs int64  `json:"durationMs"`
	Gaps       []Gap  `json:"gaps,omitempty"`
	Data       any    `json:"data,omitempty"`
}

// Agent describes the collector itself: which key tokens are made with and
// what the agent was allowed to see.
type Agent struct {
	KeyID  string   `json:"keyId"`
	UID    int      `json:"uid"`
	CapEff []string `json:"capEff"`
}

// Data is the payload of the security snapshot.
type Data struct {
	SchemaVersion int                `json:"schemaVersion"`
	Trigger       string             `json:"trigger"`
	Agent         Agent              `json:"agent"`
	Environment   Section            `json:"environment"`
	Sections      map[string]Section `json:"sections"`
}

// ok returns a fully collected section.
func ok(data any) Section { return Section{Status: StatusOK, Data: data} }

// unknown returns a section that could not be collected.
func unknown(r Reason) Section { return Section{Status: StatusUnknown, Reason: r} }

// collected returns ok, or partial when some sources were unreadable.
func collected(gaps []Gap, data any) Section {
	if len(gaps) == 0 {
		return ok(data)
	}
	return Section{Status: StatusPartial, Gaps: gaps, Data: data}
}

// absent is the section of a component that is not there: na, unless a
// source that would have told was unreadable — unknown with its reason then.
func absent(gaps gapList) Section {
	if len(gaps) > 0 {
		return unknown(gaps[0].Reason)
	}
	return Section{Status: StatusNA}
}

// gapList collects the sources a section could not read.
type gapList []Gap

// add records path as a gap unless err is nil. path is relative to the scan
// root, as the host sees it.
func (g *gapList) add(path string, err error) {
	if err != nil {
		*g = append(*g, Gap{Path: path, Reason: reasonOf(err)})
	}
}

// optional is add for a source that may legitimately be absent (a feature
// the kernel was built without): not-exist is not a gap.
func (g *gapList) optional(path string, err error) {
	if !errors.Is(err, fs.ErrNotExist) {
		g.add(path, err)
	}
}

// errParse marks content the collector could not parse.
var errParse = errors.New("security: parse error")

// reasonError carries the reason of another section as an error, for a gap
// of a section that depends on it.
type reasonError Reason

func (r reasonError) Error() string { return string(r) }

// reasonOf maps a read error to the reason reported for it.
func reasonOf(err error) Reason {
	var re reasonError
	switch {
	case errors.As(err, &re):
		return Reason(re)
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermissionDenied
	case errors.Is(err, fs.ErrNotExist):
		return ReasonNotFound
	case errors.Is(err, errTooLarge):
		return ReasonBudgetExceeded
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		errors.Is(err, os.ErrDeadlineExceeded): // a socket's timeout
		return ReasonTimeout
	case errors.Is(err, errNotRegular), errors.Is(err, errPseudoFS),
		errors.Is(err, syscall.ENOTDIR), // O_DIRECTORY on a FIFO or a file
		errors.Is(err, syscall.ELOOP):   // O_NOFOLLOW on a symlink
		return ReasonNotRegular
	case errors.Is(err, errRemoteFS):
		return ReasonRemoteFSSkipped
	case errors.Is(err, errParse):
		return ReasonParseError
	default:
		return ReasonIOError
	}
}
