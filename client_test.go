package okta

import (
	"context"
	"github.com/wearefair/okta-auth/factors"
	"testing"
)

func TestNew(t *testing.T) {

	t.Run("new with config that is missing okta domain returns error", func(t *testing.T) {
		_, err := New(ClientConfig{OktaDomain: "", Prompts: TestPrompts{}})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("new with config that is missing prompts returns error", func(t *testing.T) {
		_, err := New(ClientConfig{OktaDomain: "test.okta.com"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("new with config where okta domain does not contain scheme, sets rootURL with https scheme", func(t *testing.T) {
		client, err := New(ClientConfig{OktaDomain: "test.okta.com", Prompts: TestPrompts{}})
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		if client.rootURL != "https://test.okta.com" {
			t.Errorf("expected https://test.okta.com rootURL, got %s", client.rootURL)
		}
	})

	t.Run("new with config where okta domain contains https scheme, sets rootURL with https scheme", func(t *testing.T) {
		client, err := New(ClientConfig{OktaDomain: "https://test.okta.com", Prompts: TestPrompts{}})
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		if client.rootURL != "https://test.okta.com" {
			t.Errorf("expected https://test.okta.com rootURL, got %s", client.rootURL)
		}
	})

	t.Run("with config where okta domain contains http scheme and path, sets rootURL with http scheme and without path", func(t *testing.T) {
		client, err := New(ClientConfig{OktaDomain: "http://test.okta.com/api/v1", Prompts: TestPrompts{}})
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		if client.rootURL != "http://test.okta.com" {
			t.Errorf("expected http://test.okta.com rootURL, got %s", client.rootURL)
		}
	})
}

// --- test data ---

type TestPrompts struct {}

func (t TestPrompts) CheckU2FPresence(request VerifyU2FRequest) bool {
	return false
}

func (t TestPrompts) ChooseFactor(factors []factors.Factor) (factors.Factor, error) {
	return factors[0], nil
}

func (t TestPrompts) PresentUserError(string) {

}

func (t TestPrompts) VerifyU2F(ctx context.Context, request VerifyU2FRequest) (VerifyU2FResponse, error) {
	return VerifyU2FResponse{}, nil
}

func (t TestPrompts) VerifyCode(factor factors.Factor) (string, error) {
	return "", nil
}

func (t TestPrompts) VerifyPush() {

}

