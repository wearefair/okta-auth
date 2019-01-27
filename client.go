package okta

import (
	"context"
	"fmt"
	"net/http"

	"github.com/wearefair/okta-auth/factors"
)

// Interface for logging debug logs.
type DebugLogger interface {
	Log(string)
}

type ClientConfig struct {
	// Your organizations Okta domain (<your-org>.okta.com).
	OktaDomain string

	// Callbacks for handling user and factor interaction.
	Prompts Prompts

	// An optional RoundTripper that can be used to modify the request/response.
	// Ex: Add a custom user-agent to all requests.
	RoundTripper http.RoundTripper

	// Optional logger that when provided enables debug logs.
	DebugLogger DebugLogger
}

// Parameters used for authenticating with a U2F device.
// For more information see https://fidoalliance.org/specifications/
type VerifyU2FRequest struct {
	Facet     string
	AppId     string
	KeyHandle string
	Challenge string
}

// Data returned after successfully authenticating with a U2F device.
// For more information see https://fidoalliance.org/specifications/
type VerifyU2FResponse struct {
	ClientData    string
	SignatureData string
}

type Prompts interface {
	// Given a VerifyU2FRequest, should return true if the U2F device is present.
	// This is used to automatically choose the U2F device for MFA if it is detected.
	//
	// The Challenge field will not be set on this call.
	// This should set the "check only" field on the u2f authentication request.
	CheckU2FPresence(request VerifyU2FRequest) bool

	// Given a list of factors, should present the user with the choices and
	// return the chosen factor. If an error is returned the authentication flow
	// is aborted.
	ChooseFactor(factors []factors.Factor) (factors.Factor, error)

	// Called when there is a (retriable) error in the flow that should be presented to the user.
	// For example, if the wrong code has been entered in an SMS MFA flow, the user will be notified
	// and then prompted to choose a factor again.
	PresentUserError(string)

	// Attempt to authenticate with the chosen U2F device.
	// The context has a deadline set on it, which after it occurs the factor verification will be canceled.
	VerifyU2F(ctx context.Context, request VerifyU2FRequest) (VerifyU2FResponse, error)

	// Prompt the user for a code for the given factor (SMS, TOTP, Call).
	VerifyCode(factor factors.Factor) (string, error)
}

type OktaClient struct {
	domain     string
	httpClient *http.Client
	logger     DebugLogger
	prompts    Prompts
}

// Constructs a new OktaClient with the given config.
//
// The only required arguments are the OktaDomain, and Prompts.
// An error is returned if either of those arguments are omitted.
func New(conf ClientConfig) (*OktaClient, error) {
	if conf.OktaDomain == "" {
		return nil, fmt.Errorf("ClientConfig.OktaDomain can't be blank")
	}

	if conf.Prompts == nil {
		return nil, fmt.Errorf("ClientConfig.Prompts can't be nil")
	}

	return &OktaClient{
		domain:  "https://" + conf.OktaDomain,
		prompts: conf.Prompts,
		logger:  conf.DebugLogger,
		httpClient: &http.Client{
			Transport: conf.RoundTripper,
		},
	}, nil
}

func (c *OktaClient) log(formatString string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Log(fmt.Sprintf(formatString, args...))
	}
}
