package okta

import (
	"encoding/json"
	"strings"
	"time"
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

type Factors []Factor

func (f Factors) Len() int { return len(f) }

func (f Factors) Swap(i, j int) {
	a := f[i]
	f[i] = f[j]
	f[j] = a
}

func (f Factors) Less(i, j int) bool {
	iType := f[i].FactorType
	jType := f[j].FactorType

	iIndex := indexOfFactorType(iType)
	jIndex := indexOfFactorType(jType)

	if iIndex != -1 {
		if jIndex == -1 {
			return true
		}
		return iIndex < jIndex
	} else if jIndex != -1 {
		return false
	}

	// Fallback case if for some reason we forgot to define the type in the ordered list.
	return strings.Compare(string(iType), string(jType)) == -1
}

func (f Factors) SupportedFactors() Factors {
	supported := Factors{}
	for i, factor := range f {
		if indexOfFactorType(factor.FactorType) != -1 {
			supported = append(supported, f[i])
		}
	}
	return supported
}

type Factor struct {
	Id         string
	FactorType FactorType
	Provider   string
	Profile    interface{}
	Links      Links
	Embedded   FactorEmbedded
}

type factorHelper struct {
	Id         string
	FactorType FactorType
	Provider   string
	Profile    json.RawMessage
	Links      Links          `json:"_links,omitempty"`
	Embedded   FactorEmbedded `json:"_embedded,omitempty"`
}

func (f *Factor) UnmarshalJSON(data []byte) error {
	factor := factorHelper{}
	err := json.Unmarshal(data, &factor)
	if err != nil {
		return err
	}
	f.Id = factor.Id
	f.FactorType = factor.FactorType
	f.Provider = factor.Provider
	f.Links = factor.Links
	f.Embedded = factor.Embedded

	// Bail early if the profile is empty.
	// This can be the case when the user has not enrolled any factors.
	if len(factor.Profile) == 0 {
		return nil
	}

	switch f.FactorType {
	case FactorTypeQuestion:
		profile := FactorProfileQuestion{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case FactorTypeSMS:
		profile := FactorProfileSMS{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case FactorTypeCall:
		profile := FactorProfileCall{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case FactorTypeToken, FactorTypeTokenSoftwareTOTP, FactorTypeTokenHardware:
		profile := FactorProfileToken{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case FactorTypeU2F:
		profile := FactorProfileU2F{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	default:
		// Ignore any profile contents we don't understand
		return nil
	}

	return err
}

type FactorEmbedded struct {
	Challenge Challenge
}

type Challenge struct {
	Nonce          string
	TimeoutSeconds int
}

type FactorProfileQuestion struct {
	Question     string `json:"question,omitempty"`
	QuestionText string `json:"questionText,omitempty"`
	Answer       string `json:"answer,omitempty"`
}

type FactorProfileSMS struct {
	PhoneNumber string `json:"phoneNumber,omitempty"`
}

type FactorProfileCall struct {
	PhoneNumber    string `json:"phoneNumber,omitempty"`
	PhoneExtension string `json:"phoneExtension,omitempty"`
}

type FactorProfileToken struct {
	CredentialId string `json:"credentialId,omitempty"`
}

type FactorProfileU2F struct {
	CredentialId string `json:"credentialId,omitempty"`
	AppId        string `json:"appId,omitempty"`
	Version      string `json:"version,omitempty"`
}

type FactorChallengeU2F struct {
	Nonce          string
	TimeoutSeconds int
}

type FactorVerify struct {
	StateToken string `json:"stateToken"`
}

// Used for SMS, TOTP and Call
type FactorVerifyCode struct {
	FactorVerify
	PassCode string `json:"passCode"`
}

type FactorVerifyU2F struct {
	FactorVerify
	ClientData    string `json:"clientData"`
	SignatureData string `json:"signatureData"`
}

type FactorType string

const (
	FactorTypePush              = FactorType("push")
	FactorTypeSMS               = FactorType("sms")
	FactorTypeCall              = FactorType("call")
	FactorTypeU2F               = FactorType("u2f")
	FactorTypeToken             = FactorType("token")
	FactorTypeTokenSoftwareTOTP = FactorType("token:software:totp")
	FactorTypeTokenHardware     = FactorType("token:hardware")
	FactorTypeQuestion          = FactorType("question")
)

var preferedFactorOrder = []FactorType{
	FactorTypeU2F,
	FactorTypeToken,
	FactorTypeTokenSoftwareTOTP,
	FactorTypeTokenHardware,
	FactorTypePush,
	FactorTypeSMS,
	FactorTypeCall,
	FactorTypeQuestion,
}

func indexOfFactorType(factorType FactorType) int {
	for i, t := range preferedFactorOrder {
		if factorType == t {
			return i
		}
	}
	return -1
}

type FactorResult string

const (
	FactorResultWaiting            = FactorResult("WAITING")
	FactorResultCancelled          = FactorResult("CANCELLED")
	FactorResultTimeout            = FactorResult("TIMEOUT")
	FactorResultTimeWindowExceeded = FactorResult("TIME_WINDOW_EXCEEDED")
	FactorResultPasscodeReplayed   = FactorResult("PASSCODE_REPLAYED")
	FactorResultError              = FactorResult("ERROR")
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

// Used to indicate that the current authentication flow cannot proceed.
// When a terminal error is returned, the program should print the error and
// exit with a non zero status code.
type TerminalError string

func (e TerminalError) String() string { return string(e) }
func (e TerminalError) Error() string  { return string(e) }

type Links struct {
	Verify Link
	Cancel Link
	Next   Link
	Prev   Link
}

type Link struct {
	HREF string `json:"href"`
}
