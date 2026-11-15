package nftables

import (
	"encoding/binary"
	"slices"
	"syscall"
)

// Builders of kernel replies for synthetic cases.

func nla(typ uint16, data []byte) []byte {
	b := binary.NativeEndian.AppendUint16(nil, uint16(nlaHdrLen+len(data)))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func nest(typ uint16, attrs ...[]byte) []byte { return nla(typ|0x8000, cat(attrs...)) } // NLA_F_NESTED

func str(s string) []byte { return append([]byte(s), 0) }

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func nlmsg(typ, flags uint16, payload []byte) []byte {
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(payload))
	binary.NativeEndian.PutUint32(b, uint32(nlmsgHdrLen+len(payload)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	return append(b, payload...)
}

// nfmsg is an nf_tables message of a reply.
func nfmsg(msg uint16, f Family, flags uint16, attrs ...[]byte) []byte {
	payload := append([]byte{byte(f), 0, 0, 0}, cat(attrs...)...)
	return nlmsg(subsysNFTables<<8|msg, flags|0x2, payload) // NLM_F_MULTI
}

func doneMsg() []byte { return nlmsg(nlmsgDone, 0x2, make([]byte, 4)) }

func errMsg(errno syscall.Errno) []byte { return nlmsg(nlmsgError, 0, negErrno(errno)) }

// negErrno is the error code of NLMSG_ERROR and NLMSG_DONE: -errno.
func negErrno(errno syscall.Errno) []byte {
	return binary.NativeEndian.AppendUint32(nil, uint32(-int32(errno)))
}

func ackMsg() []byte { return nlmsg(nlmsgError, 0, make([]byte, 4)) }

func cat(msgs ...[]byte) []byte { return slices.Concat(msgs...) }

// genReply is the exchange of a generation request.
func genReply(id uint32) Record {
	return reply(reqGen, nfmsg(msgNewGen, FamilyUnspec, 0, nla(attrGenID, be32(id))), ackMsg())
}

func tableMsg(f Family, name string) []byte {
	return nfmsg(msgNewTable, f, 0, nla(attrTableName, str(name)), nla(attrTableFlags, be32(0)))
}

// baseChainMsg is a filter base chain on a hook.
func baseChainMsg(f Family, table, name string, hook, policy uint32) []byte {
	return nfmsg(msgNewChain, f, 0,
		nla(attrChainTable, str(table)), nla(attrChainName, str(name)),
		nest(attrChainHook, nla(attrHookNum, be32(hook)), nla(attrHookPriority, be32(0))),
		nla(attrChainPolicy, be32(policy)), nla(attrChainType, str("filter")))
}

func chainMsg(f Family, table, name string) []byte {
	return nfmsg(msgNewChain, f, 0, nla(attrChainTable, str(table)), nla(attrChainName, str(name)))
}

// ruleMsg is a rule of ip filter.
func ruleMsg(chain string, exprs ...[]byte) []byte {
	list := make([][]byte, 0, len(exprs))
	for _, e := range exprs {
		list = append(list, nest(attrListElem, e))
	}
	return nfmsg(msgNewRule, FamilyIP, 0, nla(attrRuleTable, str("filter")), nla(attrRuleChain, str(chain)), nest(attrRuleExprs, list...))
}

// ex is one expression: its name and data attributes.
func ex(name string, data ...[]byte) []byte {
	return cat(nla(attrExprName, str(name)), nest(attrExprData, data...))
}

func verdict(code int32, chain string) []byte {
	v := [][]byte{nla(verdictCode, be32(uint32(code)))}
	if chain != "" {
		v = append(v, nla(verdictName, str(chain)))
	}
	return ex("immediate", nla(immDreg, be32(regVerdict)), nest(immData, nest(dataVerdict, v...)))
}

func counter() []byte { return ex("counter") }

// fakeKernel answers requests from a list of exchanges, in order, as Replay.
func fakeKernel(ex ...Record) *Replay { return &Replay{exchanges: ex} }

func reply(req Request, msgs ...[]byte) Record {
	return Record{Request: req, Reply: [][]byte{cat(msgs...)}}
}

var (
	reqGen    = Request{Type: RequestGen}
	reqTables = Request{Type: RequestTables}
	reqChains = Request{Type: RequestChains}
)

// reqRules asks for the rules of a chain of ip filter.
func reqRules(chain string) Request {
	return Request{Type: RequestRules, Family: FamilyIP, Table: "filter", Chain: chain}
}
