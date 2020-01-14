package api

import (
	"encoding/json"

	"github.com/wearefair/okta-auth/factors"
)

type Factors []Factor

// Filters out factors we don't currently support.
func (f Factors) SupportedFactors() Factors {
	supported := Factors{}
	for i, factor := range f {
		if indexOfFactorType(factor.FactorType) != -1 {
			supported = append(supported, f[i])
		}
	}
	return supported
}

// https://developer.okta.com/docs/api/resources/authn#factor-object
type Factor struct {
	Id         string
	FactorType factors.FactorType
	Provider   string
	// https://developer.okta.com/docs/api/resources/factors#factor-profile-object
	Profile  interface{}
	Links    Links
	Embedded FactorEmbedded
}

// Used for unmarshalin
type factorHelper struct {
	Id         string
	FactorType factors.FactorType
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
	case factors.FactorTypeQuestion:
		profile := FactorProfileQuestion{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case factors.FactorTypeSMS:
		profile := FactorProfileSMS{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case factors.FactorTypeCall:
		profile := FactorProfileCall{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case factors.FactorTypeToken, factors.FactorTypeTokenSoftwareTOTP, factors.FactorTypeTokenHardware:
		profile := FactorProfileToken{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case factors.FactorTypeU2F:
		profile := FactorProfileU2F{}
		err = json.Unmarshal([]byte(factor.Profile), &profile)
		f.Profile = profile
	case factors.FactorTypeWebAuthN:
		profile := FactorProfileWebAuthN{}
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
	Challenge      string
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

type FactorProfileWebAuthN struct {
	CredentialId string `json:"credentialId,omitempty"`
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

type FactorVerifyPush struct {
	FactorVerify
}

type FactorVerifyWebAuthN struct {
	FactorVerify
	ClientData        string `json:"clientData"`
	SignatureData     string `json:"signatureData"`
	AuthenticatorData string `json:"authenticatorData"`
}

func indexOfFactorType(factorType factors.FactorType) int {
	for i, t := range knownFactors {
		if factorType == t {
			return i
		}
	}
	return -1
}

var knownFactors = []factors.FactorType{
	factors.FactorTypeU2F,
	factors.FactorTypeWebAuthN,
	factors.FactorTypeToken,
	factors.FactorTypeTokenSoftwareTOTP,
	factors.FactorTypeTokenHardware,
	factors.FactorTypePush,
	factors.FactorTypeSMS,
	factors.FactorTypeCall,
	factors.FactorTypeQuestion,
}
