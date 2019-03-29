package api

import (
	"time"
)

type FactorResult string

const (
	FactorResultWaiting            = FactorResult("WAITING")
	FactorResultCancelled          = FactorResult("CANCELLED")
	FactorResultTimeout            = FactorResult("TIMEOUT")
	FactorResultTimeWindowExceeded = FactorResult("TIME_WINDOW_EXCEEDED")
	FactorResultPasscodeReplayed   = FactorResult("PASSCODE_REPLAYED")
	FactorResultError              = FactorResult("ERROR")
	FactorResultRejected           = FactorResult("REJECTED")
	FactorResultSuccess            = FactorResult("SUCCESS")
)

type TransactionState string

const (
	StateSuccess           = TransactionState("SUCCESS")
	StatePasswordWarn      = TransactionState("PASSWORD_WARN")
	StatePasswordExpired   = TransactionState("PASSWORD_EXPIRED")
	StateRecovery          = TransactionState("RECOVERY")
	StateLockedOut         = TransactionState("LOCKED_OUT")
	StateMFARequired       = TransactionState("MFA_REQUIRED")
	StateMFAChallenge      = TransactionState("MFA_CHALLENGE")
	StateMFAEnroll         = TransactionState("MFA_ENROLL")
	StateMFAEnrollActivate = TransactionState("MFA_ENROLL_ACTIVATE")
)

type APIError struct {
	ErrorCode    string
	ErrorSummary string
	ErrorLink    string
	ErrorId      string
	ErrorCauses  []APIErrorCause
}

type APIErrorCause struct {
	ErrorSummary string
}

func (apiError APIError) Error() string {
	return apiError.ErrorSummary
}

type AuthenticationRequest struct {
	Username   string                `json:"username,omitempty"`
	Password   string                `json:"password,omitempty"`
	RelayState string                `json:"relayState,omitempty"`
	Context    AuthenticationContext `json:"context,omitempty"`
}

type AuthenticationContext struct {
	DeviceToken string `json:"deviceToken,omitempty"`
}

type AuthenticationTransaction struct {
	StateToken   string           `json:"stateToken,omitempty"`
	SessionToken string           `json:"sessionToken,omitempty"`
	Status       TransactionState `json:"status,omitempty"`
	ExpiresAt    time.Time        `json: "expiresAt,omitempty"`
	RelayState   string           `json:"relayState,omitempty"`
	FactorResult FactorResult     `json:"factorResult,omitempty"`
	Embedded     Embedded         `json:"_embedded,omitempty"`
	Links        Links            `json:"_links,omitempty"`
}

type Embedded struct {
	User    User
	Factors Factors
	Factor  Factor
}

type User struct {
	Id      string
	Profile UserProfile
}

type UserProfile struct {
	Login     string
	FirstName string
	LastName  string
}

type Links struct {
	Verify Link
	Cancel Link
	Next   Link
	Prev   Link
}

type Link struct {
	HREF string `json:"href"`
}
