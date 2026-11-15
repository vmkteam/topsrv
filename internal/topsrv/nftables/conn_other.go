//go:build !linux

package nftables

import "errors"

// Conn is a stub off Linux, where nfnetlink is not.
type Conn struct{}

// Dial fails off Linux.
func Dial(string) (*Conn, error) { return nil, errors.ErrUnsupported }

// Close does nothing.
func (c *Conn) Close() error { return nil }

// Exchange fails off Linux.
func (c *Conn) Exchange(Request) ([][]byte, error) { return nil, errors.ErrUnsupported }
