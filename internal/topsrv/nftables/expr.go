package nftables

import "slices"

// match says to which packets a rule applies. The order is precedence: one
// known match makes a rule conditional, else one unknown expression
// undecided.
type match int

const (
	// unconditional: statements only (counter, log), the rule applies to
	// every packet that reaches it.
	unconditional match = iota
	// undecided: an expression this decoder does not know, and no known
	// match. It may be a statement or a match: taken for either, an
	// "unknown + drop" rule would read as an unconditional drop.
	undecided
	// conditional: a known match or load, which ends the rule early for the
	// packets it does not take (NFT_BREAK).
	conditional
)

// Verdicts of a rule and ends of a chain.
const (
	VerdictNone     = ""       // the rule decides nothing: the next rule follows
	VerdictAccept   = "accept" // ends the base chain; later base chains still see the packet
	VerdictDrop     = "drop"
	VerdictReject   = "reject" // a drop that answers the sender
	VerdictQueue    = "queue"  // to a userspace program, which decides
	VerdictContinue = "continue"
	VerdictReturn   = "return"
	VerdictJump     = "jump"
	VerdictGoto     = "goto"
	VerdictUnknown  = "unknown" // a verdict code or terminal statement not known here
)

// rule is what the decoder tells of a rule, or of one of its expressions:
// whether it applies to every packet, and its verdict.
type rule struct {
	match   match
	verdict string
	chain   string // the target of jump and goto
}

// Expression attributes read (NFTA_<EXPR>_*).
const (
	attrListElem = 1
	attrExprName = 1
	attrExprData = 2

	immDreg     = 1 // NFTA_IMMEDIATE_DREG
	immData     = 2
	dataVerdict = 2 // NFTA_DATA_VERDICT
	verdictCode = 1
	verdictName = 2 // NFTA_VERDICT_CHAIN

	metaSreg    = 3 // NFTA_META_SREG: "meta mark set", not a load
	ctSreg      = 4
	payloadSreg = 5
	objrefType  = 1 // NFTA_OBJREF_IMM_TYPE
	xtName      = 1 // NFTA_MATCH_NAME, NFTA_TARGET_NAME

	regVerdict = 0 // NFT_REG_VERDICT
)

// Object types of objref (NFT_OBJECT_*).
const (
	objCounter   = 1
	objQuota     = 2
	objCTHelper  = 3
	objLimit     = 4
	objConnlimit = 5
	objTunnel    = 6
	objCTTimeout = 7
	objSecmark   = 8
	objCTExpect  = 9
	objSynproxy  = 10
)

// Verdict codes besides the netfilter ones (NFT_*).
const (
	nftContinue = -1
	nftBreak    = -2
	nftJump     = -3
	nftGoto     = -4
	nftReturn   = -5
)

// statementExprs never end a rule and set no verdict. numgen and hash only
// load a number; the match is the cmp or map after them.
var statementExprs = []string{"counter", "log", "notrack", "last", "bitwise", "byteorder", "dup", "flow_offload", "numgen", "hash"}

// conditionExprs match, or load something that may be missing: either ends
// the rule for some packets.
var conditionExprs = []string{
	"cmp", "lookup", "range", "limit", "quota", "connlimit", "dynset",
	"exthdr", "fib", "rt", "socket", "osf", "xfrm", "tunnel", "inner", "tproxy",
}

// xtStatements are iptables extensions (xt match and xt target, kept by
// iptables-nft when there is no native form) that change nothing of the
// verdict.
var xtStatements = []string{"comment", "LOG", "NFLOG", "MARK", "CONNMARK", "CT", "TRACE", "CLASSIFY", "DSCP", "TOS", "TCPMSS", "CHECKSUM", "SET", "AUDIT"}

// decodeRule reads the table, the chain and the expressions of a rule.
func decodeRule(b []byte) (table, chain string, r rule, err error) {
	attrs, err := parseAttrs(b)
	if err != nil {
		return "", "", rule{}, err
	}
	t, ok1 := find(attrs, attrRuleTable)
	c, ok2 := find(attrs, attrRuleChain)
	if !ok1 || !ok2 {
		return "", "", rule{}, ErrMalformed
	}
	var list []attr
	if a, ok := find(attrs, attrRuleExprs); ok {
		if list, err = a.nested(); err != nil {
			return "", "", rule{}, err
		}
	}
	for _, elem := range list {
		if elem.typ != attrListElem {
			continue
		}
		e, err := decodeExpr(elem)
		if err != nil {
			return "", "", rule{}, err
		}
		r.match = max(r.match, e.match)
		if r.verdict == VerdictNone && e.verdict != VerdictNone {
			r.verdict, r.chain = e.verdict, e.chain // the first verdict ends the rule
		}
	}
	return t.string(), c.string(), r, nil
}

func decodeExpr(elem attr) (rule, error) {
	attrs, err := elem.nested()
	if err != nil {
		return rule{}, err
	}
	n, ok := find(attrs, attrExprName)
	if !ok {
		return rule{}, ErrMalformed
	}
	var data []attr
	if d, ok := find(attrs, attrExprData); ok {
		if data, err = d.nested(); err != nil {
			return rule{}, err
		}
	}
	switch name := n.string(); {
	case slices.Contains(statementExprs, name):
		return rule{match: unconditional}, nil
	case slices.Contains(conditionExprs, name):
		return rule{match: conditional}, nil
	case name == "immediate":
		return decodeImmediate(data)
	case name == "meta":
		return loadOrSet(data, metaSreg), nil
	case name == "ct":
		return loadOrSet(data, ctSreg), nil
	case name == "payload":
		return loadOrSet(data, payloadSreg), nil
	case name == "objref":
		return decodeObjref(data)
	case name == "reject":
		return rule{match: unconditional, verdict: VerdictReject}, nil
	case name == "queue":
		return rule{match: unconditional, verdict: VerdictQueue}, nil
	case name == "match":
		return decodeXT(data, false), nil
	case name == "target":
		return decodeXT(data, true), nil
	}
	return rule{match: undecided}, nil
}

// loadOrSet: meta, ct and payload load into a register — a load that may
// find nothing, and a match follows — or, with a source register, set a
// value: a statement.
func loadOrSet(data []attr, sreg uint16) rule {
	if _, ok := find(data, sreg); ok {
		return rule{match: unconditional}
	}
	return rule{match: conditional}
}

// decodeImmediate: a value into a data register is a statement; into the
// verdict register, the verdict of the rule.
func decodeImmediate(data []attr) (rule, error) {
	dreg, ok := find(data, immDreg)
	if !ok {
		return rule{}, ErrMalformed
	}
	reg, err := dreg.u32()
	if err != nil {
		return rule{}, err
	}
	if reg != regVerdict {
		return rule{match: unconditional}, nil
	}
	imm, ok := find(data, immData)
	if !ok {
		return rule{}, ErrMalformed
	}
	immAttrs, err := imm.nested()
	if err != nil {
		return rule{}, err
	}
	vd, ok := find(immAttrs, dataVerdict)
	if !ok {
		return rule{}, ErrMalformed
	}
	v, err := vd.nested()
	if err != nil {
		return rule{}, err
	}
	c, ok := find(v, verdictCode)
	if !ok {
		return rule{}, ErrMalformed
	}
	code, err := c.u32()
	if err != nil {
		return rule{}, err
	}
	r := rule{match: unconditional, verdict: verdictOf(int32(code))}
	if r.verdict == VerdictJump || r.verdict == VerdictGoto {
		target, ok := find(v, verdictName)
		if !ok {
			return rule{}, ErrMalformed
		}
		r.chain = target.string()
	}
	return r, nil
}

func verdictOf(code int32) string {
	switch code {
	case nftContinue, nftBreak:
		return VerdictContinue
	case nftJump:
		return VerdictJump
	case nftGoto:
		return VerdictGoto
	case nftReturn:
		return VerdictReturn
	}
	if code < 0 {
		return VerdictUnknown
	}
	switch code & 0xff { // the upper bits carry a queue number or an errno
	case nfDrop:
		return VerdictDrop
	case nfAccept:
		return VerdictAccept
	case nfQueue:
		return VerdictQueue
	}
	return VerdictUnknown
}

// decodeObjref: a named quota, limit or connlimit matches, as does an
// object picked from a map; a counter, a ct helper, timeout or expectation,
// a tunnel and a secmark are statements; a synproxy ends the packet's way
// here; a type not known here is undecided.
func decodeObjref(data []attr) (rule, error) {
	t, ok := find(data, objrefType)
	if !ok {
		return rule{match: conditional}, nil // NFTA_OBJREF_SET_*: by a map
	}
	typ, err := t.u32()
	if err != nil {
		return rule{}, err
	}
	switch typ {
	case objQuota, objLimit, objConnlimit:
		return rule{match: conditional}, nil
	case objCounter, objCTHelper, objTunnel, objCTTimeout, objSecmark, objCTExpect:
		return rule{match: unconditional}, nil
	case objSynproxy:
		return rule{match: unconditional, verdict: VerdictUnknown}, nil
	}
	return rule{match: undecided}, nil
}

// decodeXT reads an iptables extension by name: REJECT is a reject, the
// statements in xtStatements are statements, any other match is a match,
// any other target unknown.
func decodeXT(data []attr, target bool) rule {
	n, _ := find(data, xtName)
	switch name := n.string(); {
	case target && name == "REJECT":
		return rule{match: unconditional, verdict: VerdictReject}
	case slices.Contains(xtStatements, name):
		return rule{match: unconditional}
	case !target:
		return rule{match: conditional}
	}
	return rule{match: undecided, verdict: VerdictUnknown}
}
