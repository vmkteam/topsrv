package nftables

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Conn is a NETLINK_NETFILTER socket. It lives for one read: a socket kept
// open gets ENOBUFS once a dump overruns its buffer.
type Conn struct {
	fd  int
	pid uint32 // the port id the kernel gave the socket
	seq uint32
	buf []byte // one datagram
}

// recvTimeout bounds one read from the socket.
const recvTimeout = 2 * time.Second

// maxReply bounds the bytes of one reply: a chain dump of a Kubernetes node
// with tens of thousands of iptables-nft chains is a few MiB.
const maxReply = 32 << 20

// recvBuf holds one datagram: the kernel builds a dump datagram of at most
// 32 KiB less the skb overhead.
const recvBuf = 32 << 10

// Dial opens a socket in the current network namespace, or in the one at
// netns (/proc/1/ns/net, /run/netns/NAME). The socket stays in the
// namespace it was made in, so only its creation switches: on a locked
// thread of a goroutine of its own, which returns to the agent's namespace
// after. If the return fails, the thread stays locked and ends with that
// goroutine: no goroutine of the agent runs in the other namespace.
func Dial(netns string) (*Conn, error) {
	if netns == "" {
		return dial()
	}
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		c, restored, err := dialIn(netns)
		if restored {
			runtime.UnlockOSThread()
		}
		ch <- result{c, err}
	}()
	r := <-ch
	return r.c, r.err
}

func dialIn(netns string) (c *Conn, restored bool, err error) {
	self, err := os.Open("/proc/self/task/" + strconv.Itoa(unix.Gettid()) + "/ns/net") // /proc/thread-self is 3.17+
	if err != nil {
		return nil, true, err
	}
	defer self.Close()
	target, err := os.Open(netns)
	if err != nil {
		return nil, true, err
	}
	defer target.Close()
	if err = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, true, fmt.Errorf("nftables: setns %s: %w", netns, err)
	}
	c, err = dial()
	if rerr := unix.Setns(int(self.Fd()), unix.CLONE_NEWNET); rerr != nil {
		if c != nil {
			c.Close()
		}
		return nil, false, fmt.Errorf("nftables: setns back: %w", rerr)
	}
	return c, true, err
}

func dial() (*Conn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nftables: socket: %w", err)
	}
	c := &Conn{fd: fd, buf: make([]byte, recvBuf)}
	if err := c.setup(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) setup() error {
	if err := unix.Bind(c.fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("nftables: bind: %w", err)
	}
	sa, err := unix.Getsockname(c.fd)
	if err != nil {
		return fmt.Errorf("nftables: getsockname: %w", err)
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return errors.New("nftables: not a netlink socket")
	}
	c.pid = nl.Pid
	tv := unix.NsecToTimeval(recvTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("nftables: timeout: %w", err)
	}
	return unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
}

// Close closes the socket.
func (c *Conn) Close() error { return unix.Close(c.fd) }

// Exchange sends a request and reads the reply up to its end: NLMSG_DONE
// of a dump, or the acknowledgement or error. Every message must answer
// this request (sequence and port id) and come from the kernel; a datagram
// cut by the buffer, or a reply past maxReply, is an error.
func (c *Conn) Exchange(req Request) ([][]byte, error) {
	c.seq++
	msg, err := req.marshal(c.seq)
	if err != nil {
		return nil, err
	}
	if err := unix.Sendto(c.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("nftables: send: %w", err)
	}
	var (
		out   [][]byte
		total int
	)
	for {
		n, from, err := unix.Recvfrom(c.fd, c.buf, unix.MSG_TRUNC)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return nil, fmt.Errorf("nftables: no reply in %v: %w", recvTimeout, os.ErrDeadlineExceeded)
		case err != nil:
			return nil, fmt.Errorf("nftables: recv: %w", err)
		case n > len(c.buf):
			return nil, fmt.Errorf("nftables: datagram of %d bytes: %w", n, ErrTooLarge)
		}
		if total += n; total > maxReply {
			return nil, ErrTooLarge
		}
		if nl, ok := from.(*unix.SockaddrNetlink); !ok || nl.Pid != 0 {
			continue // not from the kernel
		}
		d := append([]byte(nil), c.buf[:n]...)
		out = append(out, d)
		end, err := c.check(d)
		if err != nil || end {
			return out, err
		}
	}
}

// check validates the messages of a datagram and reports the end of the
// reply.
func (c *Conn) check(d []byte) (end bool, err error) {
	msgs, err := splitMessages(d)
	if err != nil {
		return false, err
	}
	for _, m := range msgs {
		if m.seq != c.seq || m.pid != c.pid {
			return false, fmt.Errorf("nftables: message for seq %d port %d, want %d %d: %w", m.seq, m.pid, c.seq, c.pid, ErrMalformed)
		}
		end = end || m.typ == nlmsgDone || m.typ == nlmsgError // a dump's end, an error or the ack of a GET
	}
	return end, nil
}
