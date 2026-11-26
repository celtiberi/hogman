package registrar

import (
	"fmt"

	"hogman/registrar/internal/store"
)

// ErrNotFound reports that a looked-up record or authenticated peer was not found.
var ErrNotFound = store.ErrNotFound

// ErrorKind classifies domain errors without coupling business logic to HTTP status codes.
type ErrorKind int

const (
	KindInvalid ErrorKind = iota + 1
	KindForbidden
	KindNotFound
	KindConflict
	KindRateLimited
	KindUnavailable
)

// Error is a caller-facing domain error returned by Service operations.
type Error struct {
	Kind       ErrorKind
	Msg        string
	RetryAfter int // optional seconds for KindRateLimited
}

func (e *Error) Error() string { return e.Msg }

func bad(f string, a ...any) error { return &Error{Kind: KindInvalid, Msg: fmt.Sprintf(f, a...)} }
func forbidden(f string, a ...any) error {
	return &Error{Kind: KindForbidden, Msg: fmt.Sprintf(f, a...)}
}
func missing(f string, a ...any) error  { return &Error{Kind: KindNotFound, Msg: fmt.Sprintf(f, a...)} }
func conflict(f string, a ...any) error { return &Error{Kind: KindConflict, Msg: fmt.Sprintf(f, a...)} }
func rateLimited(retryAfter int, f string, a ...any) error {
	return &Error{Kind: KindRateLimited, Msg: fmt.Sprintf(f, a...), RetryAfter: retryAfter}
}
func unavailable(f string, a ...any) error {
	return &Error{Kind: KindUnavailable, Msg: fmt.Sprintf(f, a...)}
}
