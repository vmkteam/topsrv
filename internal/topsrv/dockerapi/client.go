package dockerapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Limits of a conversation with dockerd. The answer of a rootless daemon,
// or of whatever listens on the path, is untrusted: it is bounded and
// parsed field by field.
const (
	DialTimeout     = time.Second
	RequestTimeout  = 5 * time.Second
	MaxResponseSize = 16 << 20
)

// ErrTooLarge is returned for an answer longer than MaxResponseSize.
var ErrTooLarge = errors.New("dockerapi: response too large")

// StatusError is an answer other than 200: no redirect is followed.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("dockerapi: status %d", e.Code) }

// apiVersionRe is the form of API-Version: 1.24 and later.
var apiVersionRe = regexp.MustCompile(`^1\.[0-9]{1,3}$`)

// Client talks to dockerd over a unix socket: GET only, one connection per
// request, no proxy, no redirect.
type Client struct {
	http       *http.Client
	apiVersion string // from Ping; requests go to /v{apiVersion}/...
}

// New returns a client of the socket at path.
func New(path string) *Client {
	dialer := &net.Dialer{Timeout: DialTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", path)
		},
		Proxy:                  nil, // HTTP_PROXY of the agent must not apply
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
		ResponseHeaderTimeout:  RequestTimeout,
	}
	return &Client{http: &http.Client{
		Transport:     transport,
		Timeout:       RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Ping asks for the API version (the API-Version header of /_ping); later
// requests use it. "" when the daemon sends none or an odd one: requests
// then go without a version.
func (c *Client) Ping(ctx context.Context) (string, error) {
	_, h, err := c.get(ctx, "/_ping")
	if err != nil {
		return "", err
	}
	if v := h.Get("Api-Version"); apiVersionRe.MatchString(v) {
		c.apiVersion = v
	}
	return c.apiVersion, nil
}

// Info is the part of /info read.
type Info struct {
	ServerVersion     string
	FirewallBackend   string   // FirewallBackend.Driver, API 1.49+; "" before
	SecurityOptions   []string // names: apparmor, seccomp, selinux, userns, rootless, cgroupns, no-new-privileges
	ContainersRunning *int
}

// Info reads /info. A field of an unexpected type is left empty: one odd
// field does not cost the rest.
func (c *Client) Info(ctx context.Context) (Info, error) {
	b, _, err := c.get(ctx, c.versioned("/info"))
	if err != nil {
		return Info{}, err
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(b, &raw); err != nil {
		return Info{}, err
	}
	var (
		info Info
		fb   struct{ Driver string }
		opts []string
	)
	var version string
	if json.Unmarshal(raw["ServerVersion"], &version) == nil {
		info.ServerVersion = version
	}
	if json.Unmarshal(raw["FirewallBackend"], &fb) == nil {
		info.FirewallBackend = fb.Driver
	}
	if json.Unmarshal(raw["SecurityOptions"], &opts) == nil {
		for _, o := range opts {
			for kv := range strings.SplitSeq(o, ",") { // "name=seccomp,profile=builtin"
				if name, ok := strings.CutPrefix(kv, "name="); ok {
					info.SecurityOptions = append(info.SecurityOptions, name)
				}
			}
		}
	}
	var running int
	if json.Unmarshal(raw["ContainersRunning"], &running) == nil {
		info.ContainersRunning = &running
	}
	return info, nil
}

// Container is the part of a /containers/json entry read.
type Container struct {
	Names []string
	Ports []Port
}

// Port is a port of a container; PublicPort > 0 when published on the host.
type Port struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

// Containers lists the running containers. An entry that does not decode
// is skipped; the count of those is returned.
func (c *Client) Containers(ctx context.Context) (list []Container, skipped int, err error) {
	b, _, err := c.get(ctx, c.versioned("/containers/json"))
	if err != nil {
		return nil, 0, err
	}
	var raw []json.RawMessage
	if err = json.Unmarshal(b, &raw); err != nil {
		return nil, 0, err
	}
	list = make([]Container, 0, len(raw))
	for _, r := range raw {
		var ct Container
		if json.Unmarshal(r, &ct) != nil {
			skipped++
			continue
		}
		list = append(list, ct)
	}
	return list, skipped, nil
}

func (c *Client) versioned(path string) string {
	if c.apiVersion == "" {
		return path
	}
	return "/v" + c.apiVersion + path
}

// get is the one request this client makes: GET, the body up to
// MaxResponseSize.
func (c *Client) get(ctx context.Context, path string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "topsrv")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &StatusError{Code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > MaxResponseSize {
		return nil, nil, ErrTooLarge
	}
	return b, resp.Header, nil
}
