package spool

import (
	"errors"
	"net/http"
	"strconv"
)

// StatusError is an HTTP response with status >= 400.
type StatusError struct {
	Code int
	Body string // start of the response body; empty when the caller keeps bodies out of logs
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return "HTTP " + strconv.Itoa(e.Code)
	}
	return "HTTP " + strconv.Itoa(e.Code) + ": " + e.Body
}

// Retryable reports whether a failed delivery may succeed later unchanged, so
// the payload belongs in the spool: network errors, timeouts, 5xx, 408, 429,
// and 401/403 — a re-issued token may not have reached the agent's config
// yet. Any other 4xx means the backend rejected the payload itself, and
// resending it would get the same answer.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var se *StatusError
	if !errors.As(err, &se) {
		return true
	}
	switch se.Code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	}
	return se.Code >= http.StatusInternalServerError
}
