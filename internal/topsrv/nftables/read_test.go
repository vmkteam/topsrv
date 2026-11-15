package nftables

import (
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRule(t *testing.T) {
	meta := func(sreg bool) []byte {
		if sreg {
			return ex("meta", nla(2, be32(3)), nla(metaSreg, be32(1)))
		}
		return ex("meta", nla(1, be32(1)), nla(2, be32(3)))
	}
	cmp := ex("cmp", nla(1, be32(1)))
	objref := func(typ uint32) []byte { return ex("objref", nla(objrefType, be32(typ)), nla(2, str("o"))) }
	xt := func(kind, name string) []byte { return ex(kind, nla(xtName, str(name))) }
	cases := []struct {
		name  string
		exprs [][]byte
		want  rule
	}{
		{"counter drop", [][]byte{counter(), verdict(nfDrop, "")}, rule{match: unconditional, verdict: VerdictDrop}},
		{"unknown expression and drop", [][]byte{ex("xyz"), verdict(nfDrop, "")}, rule{match: undecided, verdict: VerdictDrop}},
		{"rt and drop", [][]byte{ex("rt", nla(1, be32(1))), verdict(nfDrop, "")}, rule{match: conditional, verdict: VerdictDrop}},
		{"unknown with a match", [][]byte{ex("xyz"), meta(false), cmp, verdict(nfDrop, "")}, rule{match: conditional, verdict: VerdictDrop}},
		{"meta load and cmp", [][]byte{meta(false), cmp, verdict(nfAccept, "")}, rule{match: conditional, verdict: VerdictAccept}},
		{"meta set", [][]byte{ex("immediate", nla(immDreg, be32(1)), nest(immData, nla(1, be32(5)))), meta(true), verdict(nfAccept, "")}, rule{match: unconditional, verdict: VerdictAccept}},
		{"ct set", [][]byte{ex("ct", nla(2, be32(3)), nla(ctSreg, be32(1)))}, rule{match: unconditional}},
		{"payload load", [][]byte{ex("payload", nla(1, be32(1))), cmp}, rule{match: conditional}},
		{"payload set", [][]byte{ex("payload", nla(payloadSreg, be32(1)))}, rule{match: unconditional}},
		{"named counter", [][]byte{objref(objCounter), verdict(nfAccept, "")}, rule{match: unconditional, verdict: VerdictAccept}},
		{"named quota", [][]byte{objref(2), verdict(nfDrop, "")}, rule{match: conditional, verdict: VerdictDrop}},
		{"object by map", [][]byte{ex("objref", nla(4, str("m")))}, rule{match: conditional}},
		{"named ct helper", [][]byte{objref(objCTHelper), verdict(nfAccept, "")}, rule{match: unconditional, verdict: VerdictAccept}},
		{"named secmark", [][]byte{objref(objSecmark), verdict(nfAccept, "")}, rule{match: unconditional, verdict: VerdictAccept}},
		{"named synproxy", [][]byte{objref(objSynproxy)}, rule{match: unconditional, verdict: VerdictUnknown}},
		{"object of a type not known", [][]byte{objref(99), verdict(nfDrop, "")}, rule{match: undecided, verdict: VerdictDrop}},
		{"numgen loads", [][]byte{ex("numgen", nla(1, be32(1))), ex("lookup", nla(1, str("m")))}, rule{match: conditional}},
		{"reject", [][]byte{counter(), ex("reject", nla(1, be32(0)))}, rule{match: unconditional, verdict: VerdictReject}},
		{"queue", [][]byte{ex("queue")}, rule{match: unconditional, verdict: VerdictQueue}},
		{"queue verdict with a number", [][]byte{verdict(nfQueue|5<<16, "")}, rule{match: unconditional, verdict: VerdictQueue}},
		{"drop with an errno", [][]byte{verdict(nfDrop|1<<16, "")}, rule{match: unconditional, verdict: VerdictDrop}},
		{"xt REJECT", [][]byte{xt("target", "REJECT")}, rule{match: unconditional, verdict: VerdictReject}},
		{"xt LOG", [][]byte{xt("target", "LOG")}, rule{match: unconditional}},
		{"xt unknown target", [][]byte{xt("target", "TARPIT")}, rule{match: undecided, verdict: VerdictUnknown}},
		{"xt comment", [][]byte{xt("match", "comment"), verdict(nfDrop, "")}, rule{match: unconditional, verdict: VerdictDrop}},
		{"xt match", [][]byte{xt("match", "recent"), verdict(nfDrop, "")}, rule{match: conditional, verdict: VerdictDrop}},
		{"jump", [][]byte{counter(), verdict(nftJump, "ufw-before-input")}, rule{match: unconditional, verdict: VerdictJump, chain: "ufw-before-input"}},
		{"goto", [][]byte{verdict(nftGoto, "x")}, rule{match: unconditional, verdict: VerdictGoto, chain: "x"}},
		{"return", [][]byte{verdict(nftReturn, "")}, rule{match: unconditional, verdict: VerdictReturn}},
		{"continue", [][]byte{verdict(nftContinue, "")}, rule{match: unconditional, verdict: VerdictContinue}},
		{"unknown code", [][]byte{verdict(-9, "")}, rule{match: unconditional, verdict: VerdictUnknown}},
		{"unknown positive code", [][]byte{verdict(2, "")}, rule{match: unconditional, verdict: VerdictUnknown}},
		{"first verdict wins", [][]byte{ex("reject"), verdict(nfAccept, "")}, rule{match: unconditional, verdict: VerdictReject}},
		{"no expressions", nil, rule{match: unconditional}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := splitMessages(ruleMsg("INPUT", tc.exprs...))
			require.NoError(t, err)
			table, chain, r, err := decodeRule(msgs[0].data[nfgenmsgLen:])
			require.NoError(t, err)
			assert.Equal(t, "filter", table)
			assert.Equal(t, "INPUT", chain)
			assert.Equal(t, tc.want, r)
		})
	}

	malformed := []struct {
		name  string
		exprs [][]byte
	}{
		{"jump without a chain", [][]byte{verdict(nftJump, "")}},
		{"immediate without a register", [][]byte{ex("immediate")}},
		{"verdict without a code", [][]byte{ex("immediate", nla(immDreg, be32(0)), nest(immData, nest(dataVerdict)))}},
		{"expression without a name", [][]byte{nest(attrExprData)}},
		{"objref type of the wrong size", [][]byte{ex("objref", nla(objrefType, []byte{1}))}},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := splitMessages(ruleMsg("INPUT", tc.exprs...))
			require.NoError(t, err)
			_, _, _, err = decodeRule(msgs[0].data[nfgenmsgLen:])
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
}

// jumps is INPUT → c1 → … → cN, cN holding last.
func jumps(n int, last ...rule) map[chainKey][]rule {
	out := map[chainKey][]rule{}
	from := "INPUT"
	for i := 1; i <= n; i++ {
		to := "c" + strconv.Itoa(i)
		out[chainKey{FamilyIP, "filter", from}] = []rule{{match: unconditional, verdict: VerdictJump, chain: to}}
		from = to
	}
	out[chainKey{FamilyIP, "filter", from}] = last
	return out
}

func TestEnd(t *testing.T) {
	base := Chain{Family: FamilyIP, Table: "filter", Name: "INPUT", Base: true, Hook: 1, Policy: nfDrop, Type: "filter"}
	key := func(name string) chainKey { return chainKey{FamilyIP, "filter", name} }
	uncond := func(v, chain string) rule { return rule{match: unconditional, verdict: v, chain: chain} }
	cases := []struct {
		name   string
		policy uint32
		rules  map[chainKey][]rule
		want   string
	}{
		{"no rules: the policy", nfDrop, map[chainKey][]rule{key("INPUT"): {}}, VerdictDrop},
		{"matches only: the policy", nfAccept, map[chainKey][]rule{key("INPUT"): {{match: conditional, verdict: VerdictDrop}}}, VerdictAccept},
		{"last rule reject", nfAccept, map[chainKey][]rule{key("INPUT"): {{match: conditional, verdict: VerdictAccept}, uncond(VerdictReject, "")}}, VerdictReject},
		{"the first rule for every packet decides", nfDrop, map[chainKey][]rule{key("INPUT"): {uncond(VerdictAccept, ""), uncond(VerdictDrop, "")}}, VerdictAccept},
		{"unknown and drop", nfAccept, map[chainKey][]rule{key("INPUT"): {{match: undecided, verdict: VerdictDrop}}}, VerdictUnknown},
		{"unknown before a drop", nfDrop, map[chainKey][]rule{key("INPUT"): {{match: undecided}, uncond(VerdictDrop, "")}}, VerdictUnknown},
		{"counter only", nfDrop, map[chainKey][]rule{key("INPUT"): {uncond(VerdictNone, "")}}, VerdictDrop},
		{"return", nfAccept, map[chainKey][]rule{key("INPUT"): {uncond(VerdictReturn, ""), uncond(VerdictDrop, "")}}, VerdictAccept},
		{"jump to an empty chain, then the policy", nfDrop, map[chainKey][]rule{key("INPUT"): {uncond(VerdictJump, "a")}, key("a"): {}}, VerdictDrop},
		{"jump to an empty chain, then a reject", nfAccept, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "a"), uncond(VerdictReject, "")}, key("a"): {},
		}, VerdictReject},
		{"jump in the middle to an accept (firewalld trusted)", nfAccept, map[chainKey][]rule{
			key("INPUT"):   {uncond(VerdictJump, "zones"), uncond(VerdictReject, "")},
			key("zones"):   {{match: conditional, verdict: VerdictGoto, chain: "b"}, uncond(VerdictGoto, "a")},
			key("a"):       {uncond(VerdictJump, "a_allow"), uncond(VerdictAccept, "")},
			key("a_allow"): {{match: conditional, verdict: VerdictAccept}},
		}, VerdictAccept},
		{"a returning goto returns from its chain too", nfAccept, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "zones"), uncond(VerdictReject, "")},
			key("zones"): {uncond(VerdictGoto, "a"), uncond(VerdictDrop, "")},
			key("a"):     {},
		}, VerdictReject},
		{"a drop after a match that returns does not decide (ufw-not-local)", nfAccept, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "a"), uncond(VerdictJump, "b")},
			key("a"):     {{match: conditional, verdict: VerdictReturn}, uncond(VerdictDrop, "")},
			key("b"):     {},
		}, VerdictAccept},
		{"the same under a drop policy", nfDrop, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "a")},
			key("a"):     {{match: conditional, verdict: VerdictReturn}, uncond(VerdictJump, "deny")},
			key("deny"):  {uncond(VerdictReject, "")},
		}, VerdictDrop},
		{"an accept after a match that returns decides", nfDrop, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "a")},
			key("a"):     {{match: conditional, verdict: VerdictReturn}, uncond(VerdictAccept, "")},
		}, VerdictAccept},
		{"a drop after a match that goes elsewhere does not decide", nfAccept, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "a")},
			key("a"):     {{match: conditional, verdict: VerdictGoto, chain: "b"}, uncond(VerdictDrop, "")},
			key("b"):     {},
		}, VerdictAccept},
		{"a match that drops is passed over", nfAccept, map[chainKey][]rule{
			key("INPUT"): {uncond(VerdictJump, "a")},
			key("a"):     {{match: conditional, verdict: VerdictDrop}, uncond(VerdictDrop, "")},
		}, VerdictDrop},
		{"maxDepth jumps", nfAccept, jumps(maxDepth, uncond(VerdictDrop, "")), VerdictDrop},
		{"one jump more", nfAccept, jumps(maxDepth + 1), "jump:c" + strconv.Itoa(maxDepth+1)},
		{"target not read", nfAccept, map[chainKey][]rule{key("INPUT"): {uncond(VerdictJump, "a")}}, VerdictUnknown},
		{"chain not read", nfAccept, map[chainKey][]rule{}, VerdictUnknown},
		{"a policy the kernel does not set", nfQueue, map[chainKey][]rule{key("INPUT"): {}}, VerdictUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Policy = tc.policy
			v, target := (&Ruleset{rules: tc.rules}).End(c)
			if v == VerdictJump {
				v += ":" + target
			}
			assert.Equal(t, tc.want, v)
		})
	}
}

// readOnceReplies answer one read of a table with an INPUT chain whose
// rules are given, up to the generation asked again.
func readOnceReplies(gen uint32, rules ...[]byte) []Record {
	return []Record{
		genReply(gen),
		reply(reqTables, tableMsg(FamilyIP, "filter"), doneMsg()),
		reply(reqChains, baseChainMsg(FamilyIP, "filter", "INPUT", 1, nfDrop), chainMsg(FamilyIP, "filter", "a"), doneMsg()),
		reply(reqRules("INPUT"), append(rules, doneMsg())...),
	}
}

func TestRead(t *testing.T) {
	inputJumpsA := ruleMsg("INPUT", counter(), verdict(nftJump, "a"))

	t.Run("follows the final jump", func(t *testing.T) {
		ex := append(readOnceReplies(1, inputJumpsA),
			reply(reqRules("a"), ruleMsg("a", verdict(nfAccept, "")), doneMsg()),
			genReply(1))
		rs, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), rs.Gen)
		v, _ := rs.End(rs.Chains[0])
		assert.Equal(t, VerdictAccept, v)
	})

	t.Run("jumps followed maxDepth deep, no further", func(t *testing.T) {
		chains := []byte{}
		for i := 1; i <= maxDepth+1; i++ {
			chains = append(chains, chainMsg(FamilyIP, "filter", "c"+strconv.Itoa(i))...)
		}
		ex := []Record{
			genReply(1), reply(reqTables, tableMsg(FamilyIP, "filter"), doneMsg()),
			reply(reqChains, baseChainMsg(FamilyIP, "filter", "INPUT", 1, nfDrop), chains, doneMsg()),
			reply(reqRules("INPUT"), ruleMsg("INPUT", verdict(nftJump, "c1")), doneMsg()),
		}
		for i := 1; i <= maxDepth; i++ { // c7 is not asked for: a request more would not be in the recording
			name, next := "c"+strconv.Itoa(i), "c"+strconv.Itoa(i+1)
			ex = append(ex, reply(reqRules(name), ruleMsg(name, verdict(nftJump, next)), doneMsg()))
		}
		ex = append(ex, genReply(1))
		rs, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
		v, target := rs.End(rs.Chains[0])
		assert.Equal(t, VerdictJump+":c7", v+":"+target)
	})

	t.Run("a target not in the chain dump is not asked for", func(t *testing.T) {
		ex := append(readOnceReplies(1, ruleMsg("INPUT", verdict(nftJump, "bound"))), genReply(1))
		rs, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
		v, _ := rs.End(rs.Chains[0])
		assert.Equal(t, VerdictUnknown, v)
	})

	t.Run("at most maxRuleChains chains read", func(t *testing.T) {
		n := maxRuleChains + 2
		chains := make([]byte, 0, n*64)
		for i := range n {
			chains = append(chains, baseChainMsg(FamilyIP, "filter", "in"+strconv.Itoa(i), 1, nfDrop)...)
		}
		ex := make([]Record, 0, 3+maxRuleChains+1)
		ex = append(ex, genReply(1), reply(reqTables, tableMsg(FamilyIP, "filter"), doneMsg()), reply(reqChains, chains, doneMsg()))
		for i := range maxRuleChains {
			ex = append(ex, reply(reqRules("in"+strconv.Itoa(i)), doneMsg()))
		}
		ex = append(ex, genReply(1))
		rs, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
		_, ok := rs.RulesCount(rs.Chains[maxRuleChains-1])
		assert.True(t, ok)
		_, ok = rs.RulesCount(rs.Chains[maxRuleChains])
		assert.False(t, ok, "past the limit: not read")
	})

	t.Run("a rule of another chain is skipped", func(t *testing.T) {
		other := ruleMsg("OTHER", verdict(nfAccept, ""))
		ex := append(readOnceReplies(1, ruleMsg("INPUT", counter()), other), genReply(1))
		rs, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
		n, ok := rs.RulesCount(rs.Chains[0])
		require.True(t, ok)
		assert.Equal(t, 1, n)
	})

	t.Run("generation moved: read again", func(t *testing.T) {
		ex := append(readOnceReplies(1), genReply(2))
		ex = append(ex, readOnceReplies(2)...)
		ex = append(ex, genReply(2))
		rs, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
		assert.Equal(t, uint32(2), rs.Gen)
	})

	t.Run("generation moved every time", func(t *testing.T) {
		ex := make([]Record, 0, attempts*5)
		for i := range uint32(attempts) {
			ex = append(ex, readOnceReplies(i)...)
			ex = append(ex, genReply(i+10))
		}
		_, err := Read(fakeKernel(ex...), Inbound)
		require.ErrorIs(t, err, ErrInconsistent)
	})

	t.Run("interrupted dump: read again", func(t *testing.T) {
		intr := nfmsg(msgNewTable, FamilyIP, nlmFDumpIntr, nla(attrTableName, str("filter")))
		ex := make([]Record, 0, 7)
		ex = append(ex, genReply(1), reply(reqTables, intr, doneMsg()))
		ex = append(ex, readOnceReplies(1)...)
		ex = append(ex, genReply(1))
		_, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
	})

	t.Run("chain gone: read again", func(t *testing.T) {
		ex := readOnceReplies(1)
		ex[3] = reply(reqRules("INPUT"), errMsg(syscall.ENOENT))
		ex = append(ex, readOnceReplies(2)...)
		ex = append(ex, genReply(2))
		_, err := Read(fakeKernel(ex...), Inbound)
		require.NoError(t, err)
	})

	t.Run("no permission: no retry", func(t *testing.T) {
		_, err := Read(fakeKernel(reply(reqGen, errMsg(syscall.EPERM))), Inbound)
		require.ErrorIs(t, err, syscall.EPERM)
	})

	t.Run("transport error", func(t *testing.T) {
		_, err := Read(fakeKernel(), Inbound)
		require.ErrorIs(t, err, ErrNotRecorded)
	})

	t.Run("generation reply without an id", func(t *testing.T) {
		_, err := ReadGen(fakeKernel(reply(reqGen, nfmsg(msgNewGen, FamilyUnspec, 0), ackMsg())))
		require.ErrorIs(t, err, ErrMalformed)
	})

	t.Run("two generation replies", func(t *testing.T) {
		g := nfmsg(msgNewGen, FamilyUnspec, 0, nla(attrGenID, be32(1)))
		_, err := ReadGen(fakeKernel(reply(reqGen, g, g, ackMsg())))
		require.ErrorIs(t, err, ErrMalformed)
	})
}

func TestInbound(t *testing.T) {
	cases := []struct {
		c    Chain
		want bool
	}{
		{Chain{Family: FamilyIP, Base: true, Hook: 1, Type: "filter"}, true},
		{Chain{Family: FamilyINet, Base: true, Hook: 5, Type: "filter"}, true},
		{Chain{Family: FamilyNetdev, Base: true, Hook: 0, Type: "filter"}, true},
		{Chain{Family: FamilyIP6, Base: true, Hook: 2, Type: "filter"}, true},
		{Chain{Family: FamilyIP, Base: true, Hook: 3, Type: "filter"}, false}, // output
		{Chain{Family: FamilyIP, Base: true, Hook: 0, Type: "nat"}, false},    // prerouting
		{Chain{Family: FamilyIP, Base: true, Hook: 1, Type: "nat"}, false},    // nat input
		{Chain{Family: FamilyBridge, Base: true, Hook: 1, Type: "filter"}, false},
		{Chain{Family: FamilyIP, Name: DockerUser}, true},
		{Chain{Family: FamilyIP, Name: UFWUser}, true},
		{Chain{Family: FamilyIP6, Name: UFW6User}, true},
		{Chain{Family: FamilyIP, Name: "DOCKER"}, false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, Inbound(tc.c), "%+v", tc.c)
	}
}
