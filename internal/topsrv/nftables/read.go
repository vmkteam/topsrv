package nftables

import (
	"errors"
	"slices"
	"syscall"
)

// Exchanger sends a request and returns the datagrams of the reply, as
// read: a Conn, or a recording in tests.
type Exchanger interface {
	Exchange(Request) ([][]byte, error)
}

// Limits of a read.
const (
	// attempts at a consistent read: as nft, a dump the ruleset changed
	// under is read again.
	attempts = 3
	// maxDepth is how far End follows a jump or goto from a base chain:
	// firewalld 1.x nests its zones and policies five deep (filter_INPUT →
	// filter_INPUT_ZONES → filter_IN_public → filter_INPUT_POLICIES_pre →
	// filter_IN_policy_allow-host-ipv6 → its _pre chain).
	maxDepth = 6
	// maxRuleChains bounds the chains whose rules are read.
	maxRuleChains = 128
)

// ErrInconsistent means the ruleset changed during every attempt.
var ErrInconsistent = errors.New("nftables: ruleset changed during every read")

// errChanged: the ruleset changed during a read — the generation moved, or
// the kernel marked a dump as interrupted (NLM_F_DUMP_INTR).
var errChanged = errors.New("nftables: ruleset changed during the read")

// Ruleset is what a read found: every table and chain, and the rules of the
// chains asked for, summarized.
type Ruleset struct {
	Gen    uint32 // the generation, see ReadGen
	Tables []Table
	Chains []Chain
	rules  map[chainKey][]rule
}

type chainKey struct {
	family       Family
	table, chain string
}

func keyOf(c Chain) chainKey { return chainKey{c.Family, c.Table, c.Name} }

// RulesCount returns the number of rules of a chain; ok is false when they
// were not read.
func (rs *Ruleset) RulesCount(c Chain) (int, bool) {
	r, ok := rs.rules[keyOf(c)]
	return len(r), ok
}

// Chains users fill: DOCKER-USER, where Docker leaves room to filter what it
// publishes (FORWARD jumps there first), and the chains of ufw's own rules.
const (
	DockerUser = "DOCKER-USER"
	UFWUser    = "ufw-user-input"
	UFW6User   = "ufw6-user-input"
)

// inboundFamilies carry IP traffic to the host.
var inboundFamilies = []Family{FamilyIP, FamilyIP6, FamilyINet, FamilyNetdev}

// Inbound picks the chains that say what happens to inbound traffic: the
// filter base chains on input, forward and ingress of the ip, ip6, inet and
// netdev families, and the user chains of Docker and ufw.
func Inbound(c Chain) bool {
	if !c.Base {
		return c.Name == DockerUser || c.Name == UFWUser || c.Name == UFW6User
	}
	if c.Type != "filter" || !slices.Contains(inboundFamilies, c.Family) {
		return false
	}
	switch c.HookName() {
	case hookInput, hookForward, hookIngress:
		return true
	}
	return false
}

// Read reads the ruleset: the generation, every table and chain, the rules
// of the chains pick takes and of the chains their rules jump to for every
// packet (up to maxDepth), and the generation again. A read the ruleset
// changed under is repeated, up to attempts.
func Read(x Exchanger, pick func(Chain) bool) (*Ruleset, error) {
	for range attempts {
		rs, err := readOnce(x, pick)
		if !errors.Is(err, errChanged) {
			return rs, err
		}
	}
	return nil, ErrInconsistent
}

func readOnce(x Exchanger, pick func(Chain) bool) (*Ruleset, error) {
	gen, err := ReadGen(x)
	if err != nil {
		return nil, err
	}
	rs := &Ruleset{Gen: gen, rules: map[chainKey][]rule{}}
	if rs.Tables, err = dump(x, Request{Type: RequestTables}, decodeTable); err != nil {
		return nil, err
	}
	if rs.Chains, err = dump(x, Request{Type: RequestChains}, decodeChain); err != nil {
		return nil, err
	}
	if err = rs.readRules(x, pick); err != nil {
		return nil, err
	}
	after, err := ReadGen(x)
	switch {
	case err != nil:
		return nil, err
	case after != gen:
		return nil, errChanged
	}
	return rs, nil
}

// readRules reads the chains pick takes, then the targets of their
// unconditional jumps, breadth first. A target missing from the chain dump
// (a chain bound to its rule) is not asked for: End reports it as unknown.
func (rs *Ruleset) readRules(x Exchanger, pick func(Chain) bool) error {
	type item struct {
		chain Chain
		depth int
	}
	exists := make(map[chainKey]bool, len(rs.Chains))
	var queue []item
	for _, c := range rs.Chains {
		exists[keyOf(c)] = true
		if pick(c) {
			queue = append(queue, item{c, 0})
		}
	}
	for len(queue) > 0 && len(rs.rules) < maxRuleChains {
		it := queue[0]
		queue = queue[1:]
		key := keyOf(it.chain)
		if _, done := rs.rules[key]; done {
			continue
		}
		rules, err := readChainRules(x, it.chain)
		if errors.Is(err, syscall.ENOENT) {
			return errChanged // the chain went away since the chain dump
		}
		if err != nil {
			return err
		}
		rs.rules[key] = rules
		if it.depth == maxDepth {
			continue
		}
		for _, r := range rules {
			target := chainKey{key.family, key.table, r.chain}
			if r.match == unconditional && (r.verdict == VerdictJump || r.verdict == VerdictGoto) && exists[target] {
				queue = append(queue, item{Chain{Family: key.family, Table: key.table, Name: r.chain}, it.depth + 1})
			}
		}
	}
	return nil
}

// readChainRules dumps the rules of one chain. The kernel filters the dump
// by table and chain; a rule of another chain, from a kernel that does not,
// is skipped.
func readChainRules(x Exchanger, c Chain) ([]rule, error) {
	req := Request{Type: RequestRules, Family: c.Family, Table: c.Table, Chain: c.Name}
	datagrams, err := x.Exchange(req)
	if err != nil {
		return nil, err
	}
	rules := []rule{}
	err = parseReply(req, datagrams, func(f Family, b []byte) error {
		table, chain, r, derr := decodeRule(b)
		if derr == nil && f == c.Family && table == c.Table && chain == c.Name {
			rules = append(rules, r)
		}
		return derr
	})
	return rules, err
}

// ReadGen asks for the ruleset generation alone: it changes with every
// committed change, a cheap check whether the ruleset changed since a read.
// The process the kernel names in the reply (NFTA_GEN_PROC_*) is the one
// that asks, not the last to change the ruleset: that one is only in the
// NEWGEN notifications of a commit.
func ReadGen(x Exchanger) (uint32, error) {
	gens, err := dump(x, Request{Type: RequestGen}, decodeGen)
	switch {
	case err != nil:
		return 0, err
	case len(gens) != 1:
		return 0, ErrMalformed
	}
	return gens[0], nil
}

func dump[T any](x Exchanger, req Request, decode func(Family, []byte) (T, error)) ([]T, error) {
	datagrams, err := x.Exchange(req)
	if err != nil {
		return nil, err
	}
	var out []T
	err = parseReply(req, datagrams, func(f Family, b []byte) error {
		v, derr := decode(f, b)
		out = append(out, v)
		return derr
	})
	return out, err
}

// End is what happens to a packet of a base chain that no match took: the
// first rule that applies to every packet decides — a jump or goto is
// followed into its chain, up to maxDepth — and the policy when no rule
// does. Matches are passed over: a rule that accepts every packet of an
// interface is a match like any other.
//
// A drop or reject after a match that returns — or goes to a chain, which
// returns to the caller — does not decide: the chain judges only the
// packets it did not let out, and they may be the usual ones — ufw-not-local
// returns every packet for a local address before its drop. An allowlist
// chain ("return the known, drop the rest") then reads as letting packets
// through: an error towards allow, never towards deny.
//
// For a jump past maxDepth the verdict is VerdictJump and chain its target.
// VerdictUnknown when a chain on the way was not read, or a rule holds an
// expression not known here: it may apply to every packet, or not.
func (rs *Ruleset) End(c Chain) (verdict, chain string) {
	verdict, chain, through := rs.walk(c, 0)
	if through {
		return c.PolicyName(), ""
	}
	return verdict, chain
}

// walk returns the verdict of the first rule of c that applies to every
// packet, or through when the packet returns: off the end, or by return.
func (rs *Ruleset) walk(c Chain, depth int) (verdict, chain string, through bool) {
	rules, ok := rs.rules[keyOf(c)]
	if !ok {
		return VerdictUnknown, "", false
	}
	returned := false // a match let some packets out of the chain
	for _, r := range rules {
		switch r.match {
		case conditional:
			returned = returned || r.verdict == VerdictReturn || r.verdict == VerdictGoto
			continue
		case undecided:
			return VerdictUnknown, "", false
		case unconditional:
		}
		switch r.verdict {
		case VerdictNone, VerdictContinue:
			continue
		case VerdictReturn:
			return "", "", true
		case VerdictJump, VerdictGoto:
			if depth == maxDepth {
				return VerdictJump, r.chain, false
			}
			v, target, through := rs.walk(Chain{Family: c.Family, Table: c.Table, Name: r.chain}, depth+1)
			switch {
			case !through:
				return decided(v, target, returned)
			case r.verdict == VerdictGoto:
				return "", "", true // the target returns to c's caller
			}
			continue // back from a jump: the next rule
		}
		return decided(r.verdict, "", returned)
	}
	return "", "", true
}

// decided is a verdict reached in a chain: a drop or reject after a match
// that returned is not one, the packet goes on (see End).
func decided(verdict, chain string, returned bool) (string, string, bool) {
	if returned && (verdict == VerdictDrop || verdict == VerdictReject) {
		return "", "", true
	}
	return verdict, chain, false
}
