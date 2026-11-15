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
	h, err := c.do(ctx, "/_ping", func(r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
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
	SeccompProfile    string   // profile= of seccomp: builtin (default before 20.10), unconfined, or a path
	ContainersRunning *int
	SwarmState        string // Swarm.LocalNodeState: inactive, pending, active, error, locked
	SwarmManager      bool   // Swarm.ControlAvailable
	// AuthorizationPlugins counts Plugins.Authorization: with one, the
	// socket's group is not root by itself, and 401/403 are its answers.
	AuthorizationPlugins int
	// Exposed are dockerd's own warnings about the TCP hosts it listens
	// on (daemon/info.go fillAPIInfo).
	Exposed []Exposure
}

// Exposure is a TCP address of the API dockerd warns about.
type Exposure struct {
	Addr  string // host:port
	NoTLS bool   // without encryption; else TLS without client verification
}

// exposedRe is the warning fillAPIInfo writes per unprotected TCP host.
var exposedRe = regexp.MustCompile(`API is accessible on https?://(\S+) without (encryption|TLS client verification)`)

// Info reads /info. A field of an unexpected type is left empty: one odd
// field does not cost the rest.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var raw struct {
		ServerVersion, FirewallBackend, SecurityOptions, ContainersRunning, Swarm, Plugins, Warnings json.RawMessage
	}
	if err := c.get(ctx, c.versioned("/info"), func(r io.Reader) error { return json.NewDecoder(r).Decode(&raw) }); err != nil {
		return Info{}, err
	}
	var (
		info    Info
		version string
		fb      struct{ Driver string }
		opts    []string
		running int
		swarm   struct {
			LocalNodeState   string
			ControlAvailable bool
		}
		plugins  struct{ Authorization []string }
		warnings []string
	)
	if json.Unmarshal(raw.ServerVersion, &version) == nil {
		info.ServerVersion = version
	}
	if json.Unmarshal(raw.FirewallBackend, &fb) == nil {
		info.FirewallBackend = fb.Driver
	}
	if json.Unmarshal(raw.SecurityOptions, &opts) == nil {
		for _, o := range opts {
			fields := map[string]string{}
			for kv := range strings.SplitSeq(o, ",") { // "name=seccomp,profile=builtin"
				k, v, _ := strings.Cut(kv, "=")
				fields[k] = v
			}
			if name, ok := fields["name"]; ok {
				info.SecurityOptions = append(info.SecurityOptions, name)
			}
			if fields["name"] == "seccomp" {
				info.SeccompProfile = fields["profile"]
			}
		}
	}
	if json.Unmarshal(raw.ContainersRunning, &running) == nil {
		info.ContainersRunning = &running
	}
	if json.Unmarshal(raw.Swarm, &swarm) == nil {
		info.SwarmState, info.SwarmManager = swarm.LocalNodeState, swarm.ControlAvailable
	}
	if json.Unmarshal(raw.Plugins, &plugins) == nil {
		info.AuthorizationPlugins = len(plugins.Authorization)
	}
	if json.Unmarshal(raw.Warnings, &warnings) == nil {
		for _, w := range warnings {
			if m := exposedRe.FindStringSubmatch(w); m != nil {
				info.Exposed = append(info.Exposed, Exposure{Addr: m[1], NoTLS: m[2] == "encryption"})
			}
		}
	}
	return info, nil
}

// Container is the part of a /containers/json entry read.
type Container struct {
	Names      []string
	Ports      []Port
	HostConfig struct{ NetworkMode string } // "host": the host's network namespace
	Mounts     []Mount
}

// Mount is a mount of a container, as listed.
type Mount struct {
	Type   string // bind, volume, tmpfs
	Source string // the host path of a bind mount
}

// Port is a port of a container; PublicPort > 0 when published on the host.
type Port struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

// Containers lists the running containers, decoded one entry at a time:
// a host with thousands of them is not held twice in memory. An entry of an
// unexpected shape is skipped and counted.
func (c *Client) Containers(ctx context.Context) ([]Container, int, error) {
	var (
		list    []Container
		skipped int
	)
	err := c.get(ctx, c.versioned("/containers/json"), func(r io.Reader) error {
		var err error
		list, skipped, err = decodeContainers(r)
		return err
	})
	return list, skipped, err
}

func decodeContainers(r io.Reader) (list []Container, skipped int, err error) {
	dec := json.NewDecoder(r)
	t, err := dec.Token()
	if err != nil {
		return nil, 0, err
	}
	if t != json.Delim('[') {
		return nil, 0, errNotList
	}
	for dec.More() {
		var (
			ct Container
			te *json.UnmarshalTypeError
		)
		switch err = dec.Decode(&ct); {
		case errors.As(err, &te): // the entry was read whole; its shape is odd
			skipped++
		case err != nil:
			return list, skipped, err
		default:
			list = append(list, ct)
		}
	}
	return list, skipped, nil
}

var errNotList = errors.New("dockerapi: not a list")

func (c *Client) versioned(path string) string {
	if c.apiVersion == "" {
		return path
	}
	return "/v" + c.apiVersion + path
}

// get is the one request this client makes: GET, the body read by
// decode up to MaxResponseSize.
func (c *Client) get(ctx context.Context, path string, decode func(io.Reader) error) error {
	_, err := c.do(ctx, path, decode)
	return err
}

func (c *Client) do(ctx context.Context, path string, decode func(io.Reader) error) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "topsrv")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: resp.StatusCode}
	}
	return resp.Header, decode(&capped{r: resp.Body, n: MaxResponseSize})
}

// capped reads up to n bytes and fails with ErrTooLarge past them, unlike
// io.LimitReader, whose EOF would read as a truncated answer.
type capped struct {
	r io.Reader
	n int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.n <= 0 {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			return 0, ErrTooLarge
		}
		return 0, err // io.EOF: the answer ended right at the limit
	}
	p = p[:min(int64(len(p)), c.n)]
	n, err := c.r.Read(p)
	c.n -= int64(n)
	return n, err
}
