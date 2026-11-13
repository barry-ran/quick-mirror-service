// Package binding owns durable installation codes and authorization relations, not presence.
package binding

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
)

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string { return e.Code }

var (
	ErrInvalidInput        = &Error{Code: "INVALID_INPUT", Status: 422}
	ErrInvalidCodeFormat   = &Error{Code: "INVALID_CODE_FORMAT", Status: 422}
	ErrCodeInvalid         = &Error{Code: "CODE_INVALID", Status: 409}
	ErrRoleMismatch        = &Error{Code: "ROLE_MISMATCH", Status: 409}
	ErrAlreadyBound        = &Error{Code: "ALREADY_BOUND_TO_OTHER_PC", Status: 409}
	ErrNotBound            = &Error{Code: "NOT_BOUND", Status: 409}
	ErrBindingChanged      = &Error{Code: "BINDING_CHANGED", Status: 409}
	ErrRefreshNotAllowed   = &Error{Code: "REFRESH_NOT_ALLOWED", Status: 409}
	ErrCodeSpaceExhausted  = &Error{Code: "CODE_SPACE_EXHAUSTED", Status: 503}
	ErrAllocationRetry     = &Error{Code: "CODE_ALLOCATION_RETRY", Status: 503}
	ErrOutcomeUnknown      = &Error{Code: "OUTCOME_UNKNOWN", Status: 409}
	ErrIdempotencyConflict = &Error{Code: "IDEMPOTENCY_CONFLICT", Status: 409}
)

const BatchSize = 200

var codePattern = regexp.MustCompile(`^[0-9]{6}$`)
var revisionPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

func ValidCode(code string) bool { return codePattern.MatchString(code) }

type Relation struct {
	ID           string `json:"binding_id"`
	Revision     string `json:"revision"`
	PCID         string `json:"pc_id"`
	MobileID     string `json:"mobile_id"`
	Active       bool   `json:"active"`
	ClosePending bool   `json:"close_pending"`
}
type Code struct {
	Code    string    `json:"code,omitempty"`
	Bound   bool      `json:"bound"`
	Binding *Relation `json:"binding,omitempty"`
}
type Page struct {
	Items      []Relation `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
