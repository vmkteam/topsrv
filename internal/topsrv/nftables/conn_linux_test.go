package nftables

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnCheck(t *testing.T) {
	c := &Conn{pid: 42, seq: 7}
	stamp := func(m []byte, seq, pid uint32) []byte {
		binary.NativeEndian.PutUint32(m[8:], seq)
		binary.NativeEndian.PutUint32(m[12:], pid)
		return m
	}
	end, err := c.check(cat(stamp(tableMsg(FamilyIP, "t"), 7, 42), stamp(doneMsg(), 7, 42)))
	require.NoError(t, err)
	assert.True(t, end)

	end, err = c.check(stamp(tableMsg(FamilyIP, "t"), 7, 42))
	require.NoError(t, err)
	assert.False(t, end, "a dump goes on until NLMSG_DONE")

	_, err = c.check(stamp(tableMsg(FamilyIP, "t"), 6, 42))
	require.ErrorIs(t, err, ErrMalformed, "an answer to another request")
	_, err = c.check(stamp(tableMsg(FamilyIP, "t"), 7, 43))
	require.ErrorIs(t, err, ErrMalformed, "an answer for another socket")
	_, err = c.check([]byte{1, 2})
	require.ErrorIs(t, err, ErrMalformed)
}
