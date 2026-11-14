//go:build unix

package security

import "syscall"

const (
	openFlags = syscall.O_NONBLOCK | syscall.O_NOCTTY
	oNoFollow = syscall.O_NOFOLLOW
)
