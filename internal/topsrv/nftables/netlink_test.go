package nftables

import (
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseReply(t *testing.T) {
	interrupted := nfmsg(msgNewTable, FamilyIP, nlmFDumpIntr, nla(attrTableName, str("filter")))
	short := nlmsg(subsysNFTables<<8|msgNewTable, 0, nil)
	binary.NativeEndian.PutUint32(short, 8) // shorter than its header
	long := tableMsg(FamilyIP, "filter")
	binary.NativeEndian.PutUint32(long, uint32(len(long)+4))
	cases := []struct {
		name  string
		reply [][]byte
		want  error
	}{
		{"ok", [][]byte{cat(tableMsg(FamilyIP, "filter")), doneMsg()}, nil},
		{"error", [][]byte{errMsg(syscall.EPERM)}, syscall.EPERM},
		{"done with an error", [][]byte{nlmsg(nlmsgDone, 0, negErrno(syscall.ENOBUFS))}, syscall.ENOBUFS},
		{"interrupted", [][]byte{cat(interrupted, doneMsg())}, errChanged},
		{"no end", [][]byte{tableMsg(FamilyIP, "filter")}, ErrMalformed},
		{"another type", [][]byte{cat(chainMsg(FamilyIP, "filter", "INPUT"), doneMsg())}, ErrMalformed},
		{"overrun", [][]byte{nlmsg(nlmsgOverrun, 0, nil)}, ErrMalformed},
		{"short header", [][]byte{{1, 2, 3}}, ErrMalformed},
		{"length below header", [][]byte{short}, ErrMalformed},
		{"length past datagram", [][]byte{long}, ErrMalformed},
		{"no nfgenmsg", [][]byte{cat(nlmsg(subsysNFTables<<8|msgNewTable, 0, []byte{2}), doneMsg())}, ErrMalformed},
		{"error without code", [][]byte{nlmsg(nlmsgError, 0, nil)}, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dump(fakeKernel(Record{Request: reqTables, Reply: tc.reply}), reqTables, decodeTable)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("permission", func(t *testing.T) {
		_, err := dump(fakeKernel(Record{Request: reqTables, Reply: [][]byte{errMsg(syscall.EPERM)}}), reqTables, decodeTable)
		require.ErrorIs(t, err, fs.ErrPermission)
	})
	t.Run("noop skipped, datagrams joined", func(t *testing.T) {
		reply := [][]byte{cat(nlmsg(nlmsgNoop, 0, nil), tableMsg(FamilyIP, "a")), cat(tableMsg(FamilyIP6, "b"), doneMsg())}
		tables, err := dump(fakeKernel(Record{Request: reqTables, Reply: reply}), reqTables, decodeTable)
		require.NoError(t, err)
		assert.Equal(t, []Table{{Family: FamilyIP, Name: "a"}, {Family: FamilyIP6, Name: "b"}}, tables)
	})
}

func TestParseAttrs(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"shorter than a header", []byte{8, 0}},
		{"length below header", []byte{2, 0, 1, 0}},
		{"length past the end", []byte{12, 0, 1, 0, 'a', 0, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAttrs(tc.b)
			require.ErrorIs(t, err, ErrMalformed)
		})
	}

	t.Run("nested with a wrong length", func(t *testing.T) {
		bad := nest(attrChainHook, nla(attrHookNum, be32(1)), []byte{2, 0, 2, 0})
		_, err := decodeChain(FamilyIP, cat(nla(attrChainTable, str("filter")), nla(attrChainName, str("INPUT")), bad))
		require.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("number of the wrong size", func(t *testing.T) {
		_, err := decodeChain(FamilyIP, cat(nla(attrChainTable, str("filter")), nla(attrChainName, str("INPUT")), nla(attrChainPolicy, []byte{1})))
		require.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("string without NUL", func(t *testing.T) {
		tb, err := decodeTable(FamilyIP, nla(attrTableName, []byte("abc")))
		require.NoError(t, err)
		assert.Equal(t, "abc", tb.Name)
	})
}

func TestDecodeChain(t *testing.T) {
	b := cat(nla(attrChainTable, str("t")), nla(attrChainName, str("in")),
		nest(attrChainHook, nla(attrHookNum, be32(0)), nla(attrHookPriority, be32(uint32(0xffffff9c))),
			nest(attrHookDevs, nla(attrDeviceName, str("eth0")), nla(attrDeviceName, str("eth1")))),
		nla(attrChainPolicy, be32(nfDrop)), nla(attrChainType, str("filter")))
	c, err := decodeChain(FamilyNetdev, b)
	require.NoError(t, err)
	assert.Equal(t, Chain{Family: FamilyNetdev, Table: "t", Name: "in", Base: true, Hook: 0, Priority: -100,
		Policy: nfDrop, Type: "filter", Devices: []string{"eth0", "eth1"}}, c)
	assert.Equal(t, "ingress", c.HookName())
	assert.Equal(t, VerdictDrop, c.PolicyName())

	regular, err := decodeChain(FamilyIP, cat(nla(attrChainTable, str("t")), nla(attrChainName, str("x"))))
	require.NoError(t, err)
	assert.Empty(t, regular.HookName())
	assert.Empty(t, regular.PolicyName())

	noPolicy, err := decodeChain(FamilyIP, cat(nla(attrChainTable, str("t")), nla(attrChainName, str("x")),
		nest(attrChainHook, nla(attrHookNum, be32(1)), nla(attrHookPriority, be32(0)))))
	require.NoError(t, err)
	assert.Equal(t, VerdictUnknown, noPolicy.PolicyName(), "a base chain without a policy is not a drop")

	_, err = decodeChain(FamilyIP, nla(attrChainName, str("x")))
	require.ErrorIs(t, err, ErrMalformed, "no table")
}

func TestHookName(t *testing.T) {
	cases := []struct {
		f    Family
		hook uint32
		want string
	}{
		{FamilyIP, 1, "input"},
		{FamilyIP6, 2, "forward"},
		{FamilyINet, 5, "ingress"},
		{FamilyNetdev, 1, "egress"},
		{FamilyARP, 0, "input"},
		{FamilyBridge, 4, "postrouting"},
		{FamilyIP, 9, "hook9"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, Chain{Family: tc.f, Base: true, Hook: tc.hook}.HookName(), "%v %d", tc.f, tc.hook)
	}
}

func TestRequestMarshal(t *testing.T) {
	b, err := Request{Type: RequestRules, Family: FamilyIP6, Table: "filter", Chain: "INPUT"}.marshal(7)
	require.NoError(t, err)
	msgs, err := splitMessages(b)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	m := msgs[0]
	assert.Equal(t, uint16(subsysNFTables<<8|msgGetRule), m.typ)
	assert.Equal(t, uint16(nlmFRequest|nlmFDump), m.flags)
	assert.Equal(t, uint32(7), m.seq)
	assert.Equal(t, byte(FamilyIP6), m.data[0])
	attrs, err := parseAttrs(m.data[nfgenmsgLen:])
	require.NoError(t, err)
	require.Len(t, attrs, 2)
	assert.Equal(t, "filter", attrs[0].string())
	assert.Equal(t, uint16(attrRuleChain), attrs[1].typ)
	assert.Equal(t, "INPUT", attrs[1].string())

	b, err = reqGen.marshal(1)
	require.NoError(t, err)
	assert.Equal(t, uint16(nlmFRequest|nlmFAck), binary.NativeEndian.Uint16(b[6:]), "a GET, acknowledged")

	_, err = Request{Type: "sets"}.marshal(1)
	require.Error(t, err)
}

func TestFamilyJSON(t *testing.T) {
	b, err := json.Marshal(Request{Type: RequestRules, Family: FamilyINet, Table: "t", Chain: "c"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"rules","family":"inet","table":"t","chain":"c"}`, string(b))
	var r Request
	require.NoError(t, json.Unmarshal(b, &r))
	assert.Equal(t, FamilyINet, r.Family)
	require.Error(t, json.Unmarshal([]byte(`{"family":"ipx"}`), &r))
	assert.Equal(t, "family99", Family(99).String())
}
