package nftables

import (
	"encoding/json"
	"errors"
	"sync"
	"syscall"
)

// Record is a request and its reply as read, for -security-dump-netlink
// and for test fixtures: the datagrams are base64 in JSON. Errno is the
// error the request failed with, 0 for none.
type Record struct {
	Request Request  `json:"request"`
	Reply   [][]byte `json:"reply"`
	Errno   int      `json:"errno,omitempty"`
}

// Recorder passes requests to X and keeps every exchange. Safe for a
// reader that outlives its caller: JSON may run while a read goes on.
type Recorder struct {
	X Exchanger

	mu        sync.Mutex
	exchanges []Record
}

// Exchange implements Exchanger.
func (r *Recorder) Exchange(req Request) ([][]byte, error) {
	reply, err := r.X.Exchange(req)
	e := Record{Request: req, Reply: reply}
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		e.Errno = int(errno)
	}
	r.mu.Lock()
	r.exchanges = append(r.exchanges, e)
	r.mu.Unlock()
	return reply, err
}

// JSON is the recording so far, indented.
func (r *Recorder) JSON() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.MarshalIndent(r.exchanges, "", " ")
}

// Replay answers requests from a recording in the order recorded, retries
// included: a request other than the next one recorded is an error.
type Replay struct {
	exchanges []Record
	next      int
}

// NewReplay reads a recording made by Recorder.JSON.
func NewReplay(b []byte) (*Replay, error) {
	var ex []Record
	if err := json.Unmarshal(b, &ex); err != nil {
		return nil, err
	}
	return &Replay{exchanges: ex}, nil
}

// ErrNotRecorded means the request is not the next one of the recording.
var ErrNotRecorded = errors.New("nftables: request not next in the recording")

// Exchange implements Exchanger.
func (r *Replay) Exchange(req Request) ([][]byte, error) {
	if r.next == len(r.exchanges) || r.exchanges[r.next].Request != req {
		return nil, ErrNotRecorded
	}
	e := r.exchanges[r.next]
	r.next++
	if e.Errno != 0 {
		return e.Reply, syscall.Errno(e.Errno)
	}
	return e.Reply, nil
}
