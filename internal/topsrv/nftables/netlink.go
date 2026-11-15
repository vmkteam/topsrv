// Package nftables reads the nftables ruleset from the kernel over
// nfnetlink: the generation, tables, chains and the rules of the chains
// asked for, with GET requests only. It needs no library: the parsers are
// pure functions of the reply bytes and run anywhere; only the socket is
// Linux (conn_linux.go).
//
// The kernel ABI is linux/netlink.h, linux/netfilter/nfnetlink.h and
// linux/netfilter/nf_tables.h. Its constants are declared here rather than
// taken from x/sys/unix, which has them on Linux only: the parsers are
// tested on recorded replies on any platform.
package nftables

import (
	"encoding/binary"
	"errors"
	"syscall"
)

// Netlink framing. Header fields are in host byte order.
const (
	nlmsgHdrLen  = 16
	nlmsgNoop    = 1
	nlmsgError   = 2
	nlmsgDone    = 3
	nlmsgOverrun = 4

	nlmFRequest  = 0x1
	nlmFAck      = 0x4
	nlmFDumpIntr = 0x10
	nlmFDump     = 0x300

	nlaHdrLen   = 4
	nlaTypeMask = 0x3fff // without NLA_F_NESTED and NLA_F_NET_BYTEORDER
)

// nfnetlink: the message type is the subsystem << 8 | the message, and the
// payload starts with struct nfgenmsg (family, version, res_id).
const (
	nfgenmsgLen    = 4
	subsysNFTables = 10
)

// NFT_MSG_*: a GET is answered with the NEW of the same object.
const (
	msgNewTable = 0
	msgGetTable = 1
	msgNewChain = 3
	msgGetChain = 4
	msgNewRule  = 6
	msgGetRule  = 7
	msgNewGen   = 15
	msgGetGen   = 16
)

// Errors of a reply.
var (
	// ErrMalformed is a length or attribute that does not fit, or a
	// message the request does not produce.
	ErrMalformed = errors.New("nftables: malformed reply")
	// ErrTooLarge is a reply past maxReply.
	ErrTooLarge = errors.New("nftables: reply too large")
)

// Request is one GET: a dump of tables, chains or rules, or the generation.
// Family 0 asks for every family; Table and Chain narrow a rule dump.
type Request struct {
	Type   string `json:"type"` // RequestGen, RequestTables, RequestChains, RequestRules
	Family Family `json:"family"`
	Table  string `json:"table,omitempty"`
	Chain  string `json:"chain,omitempty"`
}

// Values of Request.Type.
const (
	RequestGen    = "gen"
	RequestTables = "tables"
	RequestChains = "chains"
	RequestRules  = "rules"
)

// msgTypes are the message of a request and of its answer.
func (r Request) msgTypes() (get, reply uint16, ok bool) {
	switch r.Type {
	case RequestGen:
		return msgGetGen, msgNewGen, true
	case RequestTables:
		return msgGetTable, msgNewTable, true
	case RequestChains:
		return msgGetChain, msgNewChain, true
	case RequestRules:
		return msgGetRule, msgNewRule, true
	}
	return 0, 0, false
}

// marshal builds the request message. The generation is a plain GET,
// acknowledged so that the reply has an end; the rest are dumps.
func (r Request) marshal(seq uint32) ([]byte, error) {
	get, _, ok := r.msgTypes()
	if !ok {
		return nil, errors.New("nftables: unknown request " + r.Type)
	}
	flags := uint16(nlmFRequest | nlmFDump)
	if r.Type == RequestGen {
		flags = nlmFRequest | nlmFAck
	}
	b := make([]byte, nlmsgHdrLen+nfgenmsgLen, 64)
	binary.NativeEndian.PutUint16(b[4:], subsysNFTables<<8|get)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	b[nlmsgHdrLen] = byte(r.Family) // nfgenmsg: version 0, res_id 0
	if r.Table != "" {
		b = appendStringAttr(b, attrRuleTable, r.Table)
	}
	if r.Chain != "" {
		b = appendStringAttr(b, attrRuleChain, r.Chain)
	}
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	return b, nil
}

func appendStringAttr(b []byte, typ uint16, s string) []byte {
	n := nlaHdrLen + len(s) + 1
	b = binary.NativeEndian.AppendUint16(b, uint16(n))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, s...)
	b = append(b, 0)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// message is one netlink message of a reply.
type message struct {
	typ, flags uint16
	seq, pid   uint32
	data       []byte // after the header
}

// splitMessages splits one datagram into its messages.
func splitMessages(b []byte) ([]message, error) {
	var out []message
	for len(b) > 0 {
		if len(b) < nlmsgHdrLen {
			return nil, ErrMalformed
		}
		n := uint64(binary.NativeEndian.Uint32(b))
		if n < nlmsgHdrLen || n > uint64(len(b)) {
			return nil, ErrMalformed
		}
		out = append(out, message{
			typ:   binary.NativeEndian.Uint16(b[4:]),
			flags: binary.NativeEndian.Uint16(b[6:]),
			seq:   binary.NativeEndian.Uint32(b[8:]),
			pid:   binary.NativeEndian.Uint32(b[12:]),
			data:  b[nlmsgHdrLen:n],
		})
		b = b[min(align4(n), uint64(len(b))):]
	}
	return out, nil
}

func align4(n uint64) uint64 { return (n + 3) &^ 3 }

// errno is the error of an NLMSG_ERROR or NLMSG_DONE message: nil for an
// acknowledgement or a dump that ended well.
func (m message) errno() error {
	if len(m.data) < 4 {
		return ErrMalformed
	}
	if code := int32(binary.NativeEndian.Uint32(m.data)); code < 0 {
		return syscall.Errno(-code)
	}
	return nil
}

// parseReply walks the datagrams of the reply to r and calls fn with the
// family and the attributes of each object. A dump the kernel marked as
// interrupted is read to its end and reported as errChanged.
func parseReply(r Request, datagrams [][]byte, fn func(Family, []byte) error) error {
	_, reply, ok := r.msgTypes()
	if !ok {
		return ErrMalformed
	}
	interrupted := false
	for _, d := range datagrams {
		msgs, err := splitMessages(d)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			interrupted = interrupted || m.flags&nlmFDumpIntr != 0
			switch m.typ {
			case nlmsgNoop:
				continue
			case nlmsgError, nlmsgDone:
				if err := m.errno(); err != nil {
					return err
				}
				if interrupted {
					return errChanged
				}
				return nil
			case nlmsgOverrun:
				return ErrMalformed
			case subsysNFTables<<8 | reply:
			default:
				return ErrMalformed
			}
			if len(m.data) < nfgenmsgLen {
				return ErrMalformed
			}
			if err := fn(Family(m.data[0]), m.data[nfgenmsgLen:]); err != nil {
				return err
			}
		}
	}
	return ErrMalformed // no end: the reply was cut short
}

// attr is one netlink attribute.
type attr struct {
	typ  uint16 // without the nested and byte order flags
	data []byte
}

// parseAttrs splits a run of attributes: 4-byte aligned, each length
// within what is left.
func parseAttrs(b []byte) ([]attr, error) {
	out := make([]attr, 0, 8) // a chain or a rule has a handful
	for len(b) > 0 {
		if len(b) < nlaHdrLen {
			return nil, ErrMalformed
		}
		n := uint64(binary.NativeEndian.Uint16(b))
		if n < nlaHdrLen || n > uint64(len(b)) {
			return nil, ErrMalformed
		}
		out = append(out, attr{typ: binary.NativeEndian.Uint16(b[2:]) & nlaTypeMask, data: b[nlaHdrLen:n]})
		b = b[min(align4(n), uint64(len(b))):]
	}
	return out, nil
}

// string is a NUL-terminated string attribute.
func (a attr) string() string {
	for i, c := range a.data {
		if c == 0 {
			return string(a.data[:i])
		}
	}
	return string(a.data)
}

// u32 is a 32-bit attribute; nf_tables sends numbers in network byte order.
func (a attr) u32() (uint32, error) {
	if len(a.data) != 4 {
		return 0, ErrMalformed
	}
	return binary.BigEndian.Uint32(a.data), nil
}

// nested parses the attributes inside a.
func (a attr) nested() ([]attr, error) { return parseAttrs(a.data) }

// find returns the attribute of type typ, the last one if repeated.
func find(attrs []attr, typ uint16) (attr, bool) {
	var (
		out   attr
		found bool
	)
	for _, a := range attrs {
		if a.typ == typ {
			out, found = a, true
		}
	}
	return out, found
}
