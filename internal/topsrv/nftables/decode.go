package nftables

import (
	"encoding/json"
	"strconv"
)

// Family is an nftables address family (NFPROTO_*).
type Family uint8

const (
	FamilyUnspec Family = 0
	FamilyINet   Family = 1
	FamilyIP     Family = 2
	FamilyARP    Family = 3
	FamilyNetdev Family = 5
	FamilyBridge Family = 7
	FamilyIP6    Family = 10
)

// String is the family as nft names it.
func (f Family) String() string {
	switch f {
	case FamilyUnspec:
		return "unspec"
	case FamilyINet:
		return "inet"
	case FamilyIP:
		return "ip"
	case FamilyARP:
		return "arp"
	case FamilyNetdev:
		return "netdev"
	case FamilyBridge:
		return "bridge"
	case FamilyIP6:
		return "ip6"
	}
	return "family" + strconv.Itoa(int(f))
}

// MarshalJSON writes the name, for recordings that read as nft does.
func (f Family) MarshalJSON() ([]byte, error) { return json.Marshal(f.String()) }

// UnmarshalJSON reads a name written by MarshalJSON.
func (f *Family) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for _, c := range []Family{FamilyUnspec, FamilyINet, FamilyIP, FamilyARP, FamilyNetdev, FamilyBridge, FamilyIP6} {
		if c.String() == s {
			*f = c
			return nil
		}
	}
	return ErrMalformed
}

// Attributes of the objects read (NFTA_*).
const (
	attrTableName  = 1
	attrTableFlags = 2

	attrChainTable  = 1
	attrChainName   = 3
	attrChainHook   = 4
	attrChainPolicy = 5
	attrChainType   = 7

	attrHookNum      = 1
	attrHookPriority = 2
	attrHookDev      = 3
	attrHookDevs     = 4 // a list of NFTA_DEVICE_NAME
	attrDeviceName   = 1

	attrRuleTable = 1
	attrRuleChain = 2
	attrRuleExprs = 4

	attrGenID = 1
)

// TableDormant is the flag of a table switched off: its chains are not
// registered (NFT_TABLE_F_DORMANT).
const TableDormant = 0x1

// Policies of a base chain: the netfilter verdict codes.
const (
	nfDrop   = 0
	nfAccept = 1
	nfQueue  = 3

	policyUnset = 1<<32 - 1 // no NFTA_CHAIN_POLICY: the kernel sends one for every base chain
)

// Table is an nftables table.
type Table struct {
	Family Family
	Name   string
	Flags  uint32
}

// Chain is an nftables chain; the hook fields are set for a base chain.
type Chain struct {
	Family   Family
	Table    string
	Name     string
	Base     bool
	Hook     uint32
	Priority int32
	Policy   uint32 // nfAccept or nfDrop, the only ones the kernel takes; policyUnset when not sent
	Type     string // filter, nat, route
	Devices  []string
}

// Hooks that see inbound traffic, as nft names them.
const (
	hookInput   = "input"
	hookForward = "forward"
	hookIngress = "ingress"
)

// HookName is the hook as nft names it, by family.
func (c Chain) HookName() string {
	if !c.Base {
		return ""
	}
	var names []string
	switch c.Family {
	case FamilyUnspec:
	case FamilyNetdev:
		names = []string{hookIngress, "egress"}
	case FamilyARP:
		names = []string{hookInput, "output", hookForward}
	case FamilyIP, FamilyIP6, FamilyINet, FamilyBridge:
		names = []string{"prerouting", hookInput, hookForward, "output", "postrouting", hookIngress}
	}
	if int(c.Hook) < len(names) {
		return names[c.Hook]
	}
	return "hook" + strconv.FormatUint(uint64(c.Hook), 10)
}

// PolicyName is the policy of a base chain: accept or drop; unknown for a
// value the kernel does not set.
func (c Chain) PolicyName() string {
	if !c.Base {
		return ""
	}
	switch c.Policy {
	case nfAccept:
		return VerdictAccept
	case nfDrop:
		return VerdictDrop
	}
	return VerdictUnknown
}

func decodeGen(_ Family, b []byte) (uint32, error) {
	attrs, err := parseAttrs(b)
	if err != nil {
		return 0, err
	}
	a, ok := find(attrs, attrGenID)
	if !ok {
		return 0, ErrMalformed
	}
	return a.u32()
}

func decodeTable(f Family, b []byte) (Table, error) {
	attrs, err := parseAttrs(b)
	if err != nil {
		return Table{}, err
	}
	t := Table{Family: f}
	a, ok := find(attrs, attrTableName)
	if !ok {
		return Table{}, ErrMalformed
	}
	t.Name = a.string()
	if a, ok := find(attrs, attrTableFlags); ok {
		if t.Flags, err = a.u32(); err != nil {
			return Table{}, err
		}
	}
	return t, nil
}

func decodeChain(f Family, b []byte) (Chain, error) {
	attrs, err := parseAttrs(b)
	if err != nil {
		return Chain{}, err
	}
	c := Chain{Family: f, Policy: policyUnset}
	table, ok1 := find(attrs, attrChainTable)
	name, ok2 := find(attrs, attrChainName)
	if !ok1 || !ok2 {
		return Chain{}, ErrMalformed
	}
	c.Table, c.Name = table.string(), name.string()
	if a, ok := find(attrs, attrChainType); ok {
		c.Type = a.string()
	}
	if a, ok := find(attrs, attrChainPolicy); ok {
		if c.Policy, err = a.u32(); err != nil {
			return Chain{}, err
		}
	}
	if a, ok := find(attrs, attrChainHook); ok {
		c.Base = true
		if err := decodeHook(&c, a); err != nil {
			return Chain{}, err
		}
	}
	return c, nil
}

func decodeHook(c *Chain, a attr) error {
	hook, err := a.nested()
	if err != nil {
		return err
	}
	num, ok1 := find(hook, attrHookNum)
	prio, ok2 := find(hook, attrHookPriority)
	if !ok1 || !ok2 {
		return ErrMalformed
	}
	if c.Hook, err = num.u32(); err != nil {
		return err
	}
	p, err := prio.u32()
	if err != nil {
		return err
	}
	c.Priority = int32(p)
	if dev, ok := find(hook, attrHookDev); ok {
		c.Devices = append(c.Devices, dev.string())
	}
	if devs, ok := find(hook, attrHookDevs); ok {
		list, err := devs.nested()
		if err != nil {
			return err
		}
		for _, d := range list {
			if d.typ == attrDeviceName {
				c.Devices = append(c.Devices, d.string())
			}
		}
	}
	return nil
}
