package okta

/*
Please see https://developer.okta.com/docs/api/resources/authn.html for documentation on how the okta auth flow works.

The authentication flow works by recursively calling the handleAuthUserFlow function.

After every auth operation against Okta, a new AuthenticationTransaction is returned, which gives us a few things:
1. The current state of the transaction (ex: MFA required, MFA Challenge, Locked out, etc.)
2. The links to issue post requests to in order to advance the transaction to the next step, or go to the previous step.

Given that the transaction state has everything we need to know how to proceed (or reverse), we don't need to hold
any internal state, and can instead continually evaluate the state of the transaction in a loop until we succeed
or hit a terminal error condition.

In general for an MFA flow we will first call handleMFARequired.
In this state we are given a list of all possible MFA factors that can be used.
This will prompt the user to select a factor, and post to okta to "activate" that factor for verification.

If that succeeds, the next state will call handleMFAChallenge.
Depending on the factor that was chosen, this might required the user to provide some sort of input.
If the factor is successfully verified, then we will hit the success state, and the okta session token will be returned
by the handleAuthUserFlow function.
*/

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/wearefair/okta-auth/api"
	"github.com/wearefair/okta-auth/factors"
)

const unexpectedErrorMessage = "Encountered an unexpected error."
const timeoutErrorMessage = "Authentication Timed Out"

// Custom error for handling auth timeout and rejection
type NonFatalAuthError struct {
	ErrorSummary string
}

func (nonFatalAuthError NonFatalAuthError) Error() string {
	return nonFatalAuthError.ErrorSummary
}

// Given a username and password, returns a session token or an error.
// You can then use the session token to obtain a session id.
// https://developer.okta.com/docs/api/resources/sessions#session-token
//
// If a second factor is required, the configured callbacks on the client will be invoked.
func (c *OktaClient) Authenticate(username, password string) (string, error) {
	url := c.domain + "/api/v1/authn"
	c.log("Posting auth request to %q with username %q ", url, username)

	transaction, apiError, err := c.sendTransactionRequest(url, &api.AuthenticationRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "", err
	}
	if apiError != nil {
		c.log(apiError.ErrorSummary)
		return "", errors.New("Failed to authenticate")
	}
	return c.handleAuthUserFlow(transaction, true)
}

// Given an AuthenticationTransaction executes the state machine, and eventually returns
// an error or a Okta session token.
//
// This is the entrypoint to the main recursive loop.
// All methods will eventually call this method, or return the session token or error.
func (c *OktaClient) handleAuthUserFlow(transaction api.AuthenticationTransaction, autoAttemptU2F bool) (string, error) {
	c.log("Handling auth user flow: status %q", transaction.Status)

	switch transaction.Status {
	case api.StateSuccess:
		return transaction.SessionToken, nil
	case api.StatePasswordExpired:
		return "", TerminalError(fmt.Sprintf("Your password is expired, login to %s to resolve.", c.domain))
	case api.StateRecovery:
		return "", TerminalError(fmt.Sprintf("Your account is in recovery, login to %s to resolve.", c.domain))
	case api.StateLockedOut:
		return "", TerminalError("Your account has been locked, please contact your administrator for assistance.")
	case api.StateMFAEnroll, api.StateMFAEnrollActivate:
		return "", TerminalError(fmt.Sprintf("You are required to enroll an MFA method, login to %s to resolve.", c.domain))
	case api.StateMFARequired:
		return c.handleMFARequired(transaction, autoAttemptU2F)
	case api.StateMFAChallenge:
		return c.handleMFAChallenge(transaction)
	default:
		return "", TerminalError(fmt.Sprintf("Unknown user state %s, contact your administrator for assistance.", transaction.Status))
	}
}

// If autoAttemptU2F is true, calls the user provided U2F callback to check if the device is present,
// and if so will start the U2F flow for that factor.
// Otherwise calls the user provided callback with the list of factors, which should return the user specified factor
// or an error which will cancel the flow.
func (c *OktaClient) handleMFARequired(transaction api.AuthenticationTransaction, autoAttemptU2F bool) (string, error) {
	supported := transaction.Embedded.Factors.SupportedFactors()
	if len(supported) == 0 {
		return "", TerminalError("No supported MFA types found")
	}

	// Start the mfa factor automatically if it is present, and the u2f token is connected.
	for _, factor := range supported {
		if factor.FactorType == factors.FactorTypeU2F && autoAttemptU2F &&
			c.prompts.CheckU2FPresence(u2fProfileToChallenge(c.domain, "", factor.Profile.(api.FactorProfileU2F))) {
			return c.startMFA(transaction, factor)
		}
	}

	publicFactors := apiFactorsToPublicFactors(supported)
	factor, err := c.prompts.ChooseFactor(publicFactors)
	if err != nil {
		return "", err
	}

	for _, apiFactor := range supported {
		if apiFactor.Id == factor.Id {
			return c.startMFA(transaction, apiFactor)
		}
	}

	return "", TerminalError(fmt.Sprintf("Factor with id %q was not found", factor.Id))
}

// Starts the verification flow for the given factor.
func (c *OktaClient) startMFA(transaction api.AuthenticationTransaction, factor api.Factor) (string, error) {
	newTransaction, apiError, err := c.sendTransactionRequest(factor.Links.Verify.HREF, api.FactorVerify{
		StateToken: transaction.StateToken,
	})
	if err != nil {
		return "", err
	}
	if apiError != nil {
		c.prompts.PresentUserError(fmt.Sprintf("Got error trying to use MFA %s: %s", factor.FactorType, apiError.ErrorSummary))
	}

	return c.handleAuthUserFlow(newTransaction, false)
}

// Captures user input (if required) to verify the active factor challenge.
func (c *OktaClient) handleMFAChallenge(transaction api.AuthenticationTransaction) (string, error) {
	switch transaction.Embedded.Factor.FactorType {
	case factors.FactorTypeU2F:
		return c.handleFactorTypeU2F(transaction)

	case factors.FactorTypeTokenSoftwareTOTP, factors.FactorTypeSMS, factors.FactorTypeCall:
		return c.handleFactorTypeCode(transaction)

	case factors.FactorTypePush:
		return c.handleFactorTypePush(transaction)

	default:
		return c.cancelCurrentFactorWithErrorMessage(transaction, "Sorry, that factor is not supported yet.")
	}
}

// Presents the user with the error message, and then cancels the current factor.
func (c *OktaClient) cancelCurrentFactorWithErrorMessage(transaction api.AuthenticationTransaction, msg string) (string, error) {
	c.prompts.PresentUserError(msg)
	return c.cancelCurrentFactor(transaction)
}

// Cancels the current factor, and goes back into the authentication transaction loop.
func (c *OktaClient) cancelCurrentFactor(transaction api.AuthenticationTransaction) (string, error) {
	request := &api.FactorVerify{transaction.StateToken}
	newTransaction, apiError, err := c.sendTransactionRequest(transaction.Links.Prev.HREF, request)
	if err != nil {
		return "", err
	}
	if apiError != nil {
		c.log("Got error trying to cancel MFA factor: uri %q, error: %q", transaction.Links.Prev.HREF, apiError.ErrorSummary)
		return "", TerminalError(unexpectedErrorMessage)
	}

	return c.handleAuthUserFlow(newTransaction, false)
}

func (c *OktaClient) handleFactorTypeU2F(transaction api.AuthenticationTransaction) (string, error) {
	profile, ok := transaction.Embedded.Factor.Profile.(api.FactorProfileU2F)
	if !ok {
		c.log("Profile was not of type FactorProfileU2F: %s", transaction.Embedded.Factor.Profile)
		return c.cancelCurrentFactorWithErrorMessage(transaction, unexpectedErrorMessage)
	}

	// Setup a context with the timeout set to the value provided by Okta
	timeoutSeconds := transaction.Embedded.Factor.Embedded.Challenge.TimeoutSeconds
	ctx, _ := context.WithTimeout(context.Background(), time.Second*time.Duration(timeoutSeconds))

	authResp, err := c.prompts.VerifyU2F(ctx, VerifyU2FRequest{
		Facet:     c.domain,
		AppId:     profile.AppId,
		KeyHandle: profile.CredentialId,
		Challenge: transaction.Embedded.Factor.Embedded.Challenge.Nonce,
	})
	if err != nil {
		c.prompts.PresentUserError(fmt.Sprintf("Failed to authenticate: %s\n", err))
		return c.cancelCurrentFactor(transaction)
	}

	verifyReq := api.FactorVerifyU2F{
		FactorVerify: api.FactorVerify{
			StateToken: transaction.StateToken,
		},
		ClientData:    authResp.ClientData,
		SignatureData: authResp.SignatureData,
	}
	newTransaction, apiError, err := c.sendTransactionRequest(transaction.Links.Next.HREF, &verifyReq)
	if err != nil {
		return "", err
	}
	if apiError != nil {
		return c.cancelCurrentFactorWithErrorMessage(transaction, apiError.ErrorSummary)
	}
	return c.handleAuthUserFlow(newTransaction, false)
}

func (c *OktaClient) handleFactorTypeCode(transaction api.AuthenticationTransaction) (string, error) {
	code, err := c.prompts.VerifyCode(apiFactorToPublicFactor(transaction.Embedded.Factor))
	if err != nil {
		return c.cancelCurrentFactorWithErrorMessage(transaction, "Cancelled")
	}

	verifyReq := api.FactorVerifyCode{
		FactorVerify: api.FactorVerify{
			StateToken: transaction.StateToken,
		},
		PassCode: code,
	}
	newTransaction, apiError, err := c.sendTransactionRequest(transaction.Links.Next.HREF, &verifyReq)
	if err != nil {
		return "", err
	}
	if apiError != nil {
		return c.cancelCurrentFactorWithErrorMessage(transaction, apiError.ErrorSummary)
	}
	return c.handleAuthUserFlow(newTransaction, false)
}

// Logic for handling Okta Verify Push. Given a Authentication Transaction, will make an initial call to send a push notification
// to user's device then prompts them to accept it. Uses a backoff policy to poll the verify endpoint while waiting on a user to accept.
// Important to note that if a user times out, the initial verify request will still be on their phone and they'll have to accept/reject it
// before trying again.
// TODO: Configurable timeouts
func (c *OktaClient) handleFactorTypePush(transaction api.AuthenticationTransaction) (string, error) {
	var newTransaction api.AuthenticationTransaction

	// Sends a request to Okta to push a notification to user's device
	verifyReq := api.FactorVerifyPush{
		FactorVerify: api.FactorVerify{
			StateToken: transaction.StateToken,
		},
	}
	transaction, apiError, err := c.sendTransactionRequest(transaction.Links.Next.HREF, &verifyReq)
	if err != nil {
		return c.cancelCurrentFactorWithErrorMessage(transaction, "Cancelled")
	}
	if apiError != nil {
		return c.cancelCurrentFactorWithErrorMessage(transaction, apiError.ErrorSummary)
	}

	// Prompt user to check their device for an Okta Verify notification
	c.prompts.VerifyPush()

	// Setup and begin constant backoff policy that retries every 3 seconds with a maximum of 10 attempts (timeout after 30 seconds)
	backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 10)
	operation := func() error {
		newTransaction, apiError, err = c.sendTransactionRequest(transaction.Links.Next.HREF, &verifyReq)
		if err != nil {
			return backoff.Permanent(err)
		}
		if apiError != nil {
			return backoff.Permanent(apiError)
		}
		if newTransaction.Status == api.StateSuccess {
			return nil
		}
		if newTransaction.FactorResult == api.FactorResultRejected {
			fmt.Println("Authentication Request rejected")
			return backoff.Permanent(&NonFatalAuthError{"Authentication Rejected"})
		}
		return &NonFatalAuthError{timeoutErrorMessage}
	}
	err = backoff.Retry(operation, backoffPolicy)

	// If error is a NonFatalAuthError (timeout or rejection) then cancel the transaction so we can go through the auth flow again
	if _, ok := err.(*NonFatalAuthError); ok {
		if err.Error() == timeoutErrorMessage {
			fmt.Println("Authentication Timed Out - please reject the current Okta Auth Request on your phone then try again")
		}
		c.sendTransactionRequest(newTransaction.Links.Cancel.HREF, &verifyReq)
		return "", err
	}
	if err != nil {
		return c.cancelCurrentFactorWithErrorMessage(transaction, err.Error())
	}
	return c.handleAuthUserFlow(newTransaction, false)
}

// Given a url and a pointer to a struct, serializes the request to JSON and POSTs it to the given url.
// If the status code is 200, returns a new AuthenticationTransaction.
// If the status code is 4xx returns an APIError.
// For any other error condition (5xx, JSON marshaling, etc) returns a TerminalError
func (c *OktaClient) sendTransactionRequest(url string, request interface{}) (api.AuthenticationTransaction, *api.APIError, error) {
	transaction := api.AuthenticationTransaction{}
	status, body, err := c.sendRequest(http.MethodPost, url, request)
	if err != nil {
		// Don't log the AuthenticationRequest, as that will contain a password
		if _, ok := request.(*api.AuthenticationRequest); ok {
			c.log("Got error sending transaction request: error: %s", request)
		} else {
			c.log("Got error sending transaction request: request %#+v, error: %s", request, err)
		}
		return transaction, nil, TerminalError(err.Error())
	}

	if status == http.StatusOK {
		err = json.Unmarshal(body, &transaction)
		if err != nil {
			c.log("Got error unmarshaling authentication transaction: body %q, error %s", string(body), err)
			return transaction, nil, TerminalError(unexpectedErrorMessage)
		}
		return transaction, nil, nil
	}

	if status == http.StatusTooManyRequests {
		return transaction, nil, TerminalError("Too many requests to Okta, try again later")
	}

	if status >= 400 && status < 500 {
		apiError := api.APIError{}
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			c.log("Got error unmarshaling api error: body %q, error %s", string(body), err)
			return transaction, nil, TerminalError(unexpectedErrorMessage)
		}
		return transaction, &apiError, nil
	}

	c.log("Got unexpected server status code: body %q, status %d", string(body), status)
	return transaction, nil, TerminalError(unexpectedErrorMessage)
}

// Sends an http request to with the given method and url, serializing the body to json.
// Returns the resulting status code, the body, or an error if the request failed.
func (c *OktaClient) sendRequest(method, url string, body interface{}) (int, []byte, error) {
	c.log("Sending http request %s %s", method, url)

	requestBytes, err := json.Marshal(body)
	if err != nil {
		c.log("Error marshaling body for request %s %s: %s", method, url, err)
		return 0, nil, err
	}

	request, err := http.NewRequest(method, url, bytes.NewBuffer(requestBytes))
	if err != nil {
		c.log("Error creating request %s %s: %s", method, url, err)
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)

	if err != nil {
		c.log("Error sending request %s %s: %s", method, url, err)
		return 0, nil, err
	}

	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}

	c.log("Got http response: status %d, body %q", response.StatusCode, string(bodyBytes))
	return response.StatusCode, bodyBytes, nil
}

func u2fProfileToChallenge(facet, challenge string, profile api.FactorProfileU2F) VerifyU2FRequest {
	return VerifyU2FRequest{
		AppId:     profile.AppId,
		Facet:     facet,
		KeyHandle: profile.CredentialId,
		Challenge: challenge,
	}
}

func apiFactorsToPublicFactors(facs []api.Factor) []factors.Factor {
	re := make([]factors.Factor, 0, len(facs))

	for _, f := range facs {
		re = append(re, apiFactorToPublicFactor(f))
	}
	return re
}

func apiFactorToPublicFactor(factor api.Factor) factors.Factor {
	re := factors.Factor{
		Id:         factor.Id,
		FactorType: factor.FactorType,
		Provider:   factor.Provider,
	}

	switch profile := factor.Profile.(type) {
	case api.FactorProfileQuestion:
		re.ProfileQuestion = &factors.ProfileQuestion{
			QuestionText: profile.QuestionText,
		}
	case api.FactorProfileSMS:
		re.ProfileSMS = &factors.ProfileSMS{
			PhoneNumber: profile.PhoneNumber,
		}
	case api.FactorProfileCall:
		re.ProfileCall = &factors.ProfileCall{
			PhoneNumber:    profile.PhoneNumber,
			PhoneExtension: profile.PhoneExtension,
		}
	case api.FactorProfileToken:
		re.ProfileToken = &factors.ProfileToken{
			CredentialId: profile.CredentialId,
		}
	}
	return re
}
