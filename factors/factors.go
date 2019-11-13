package factors

type FactorType string

const (
	FactorTypePush              = FactorType("push")
	FactorTypeSMS               = FactorType("sms")
	FactorTypeCall              = FactorType("call")
	FactorTypeU2F               = FactorType("u2f")
	FactorTypeWebAuthN          = FactorType("webauthn")
	FactorTypeToken             = FactorType("token")
	FactorTypeTokenSoftwareTOTP = FactorType("token:software:totp")
	FactorTypeTokenHardware     = FactorType("token:hardware")
	FactorTypeQuestion          = FactorType("question")
)

// Specifies a multi-factor method available for authentication.
// At most one of the Profile* fields will be populated depending on the FactorType.
type Factor struct {
	Id         string
	FactorType FactorType
	// https://developer.okta.com/docs/api/resources/factors#provider-type
	Provider string

	// Specifies the profile for a FactorTypeQuestion factor.
	ProfileQuestion *ProfileQuestion
	// Specifies the profile for a FactorTypeSMS factor.
	ProfileSMS *ProfileSMS
	// Specifies the profile for a FactorTypeCall factor.
	ProfileCall *ProfileCall
	// Specifies the profile for a FactorTypeToken, FactorTypeTokenHardware,
	// and FactorTypeTokenSoftwareTOTP factor.
	ProfileToken *ProfileToken
}

type ProfileQuestion struct {
	// Display text for question.
	QuestionText string
}

type ProfileSMS struct {
	// Phone number of mobile device.
	PhoneNumber string
}

type ProfileCall struct {
	// Phone number of the device.
	PhoneNumber string
	// Extension of the device.
	PhoneExtension string
}

type ProfileToken struct {
	// Id for credential. Ex: "dade.murphy@example.com"
	CredentialId string
}
