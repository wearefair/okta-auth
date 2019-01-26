package factors

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

// Specifies a multi-factor method available for authentication.
// At most one of the Profile* fields will be populated depending on the FactorType.
type Factor struct {
	Id         string
	FactorType FactorType
	// https://developer.okta.com/docs/api/resources/factors#provider-type
	Provider string

	// Specifies the profile for a FactorTypeQuestion factor.
	ProfileQuestion *FactorProfileQuestion
	// Specifies the profile for a FactorTypeSMS factor.
	ProfileSMS *FactorProfileSMS
	// Specifies the profile for a FactorTypeCall factor.
	ProfileCall *FactorProfileCall
	// Specifies the profile for a FactorTypeToken, FactorTypeTokenHardware,
	// and FactorTypeTokenSoftwareTOTP factor.
	ProfileToken *FactorProfileToken
}

type FactorProfileQuestion struct {
	// Display text for question.
	QuestionText string
}

type FactorProfileSMS struct {
	// Phone number of mobile device.
	PhoneNumber string
}

type FactorProfileCall struct {
	// Phone number of the device.
	PhoneNumber string
	// Extension of the device.
	PhoneExtension string
}

type FactorProfileToken struct {
	// Id for credential. Ex: "dade.murphy@example.com"
	CredentialId string
}
