package api

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/wearefair/okta-auth/factors"
)

func TestFactorUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		input    string
		expected Factor
	}{
		{
			input: sampleTokenFactor,
			expected: Factor{
				Id:         "uftpep6vfeujtcuPc1t6",
				FactorType: factors.FactorTypeTokenSoftwareTOTP,
				Provider:   "GOOGLE",
				Profile: FactorProfileToken{
					CredentialId: "first@example.com",
				},
				Links: Links{
					Verify: Link{
						HREF: "https://example.okta.com/api/v1/authn/factors/uftpep6vfeujtcuPc1t6/verify",
					},
				},
			},
		},
		{
			input: sampleU2FFactor,
			expected: Factor{
				Id:         "fuf59d1ohqJZyOelX1t7",
				FactorType: factors.FactorTypeU2F,
				Provider:   "FIDO",
				Profile: FactorProfileU2F{
					CredentialId: "s94CdJnUd148p95PNq7AaY2Dv1QFrLJ12Vpkno-Q7WalmBTtB5TMnzDNL_yX84Ay49qnEiUXtSx0KK5I60ht2g",
					AppId:        "https://example.okta.com",
					Version:      "U2F_V2",
				},
				Links: Links{
					Verify: Link{
						HREF: "https://example.okta.com/api/v1/authn/factors/fuf59d1ohqJZyOelX1t7/verify",
					},
				},
			},
		},
	}

	for i, testCase := range testCases {
		actual := Factor{}
		err := json.Unmarshal([]byte(testCase.input), &actual)
		if err != nil {
			t.Errorf("%0d: Error: %s\n", i, err)
			continue
		}
		if !reflect.DeepEqual(actual, testCase.expected) {
			t.Errorf("%0d: Expected:\n    %#+v\nActual:\n    %#+v\n", i, testCase.expected, actual)
		}
	}
}

var sampleTokenFactor = `
{
  "id": "uftpep6vfeujtcuPc1t6",
  "factorType": "token:software:totp",
  "provider": "GOOGLE",
  "vendorName": "GOOGLE",
  "profile": {
    "credentialId": "first@example.com"
  },
  "_links": {
    "verify": {
      "href": "https:\/\/example.okta.com\/api\/v1\/authn\/factors\/uftpep6vfeujtcuPc1t6\/verify",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}
`

var sampleU2FFactor = `
{
  "id": "fuf59d1ohqJZyOelX1t7",
  "factorType": "u2f",
  "provider": "FIDO",
  "vendorName": "FIDO",
  "profile": {
    "credentialId": "s94CdJnUd148p95PNq7AaY2Dv1QFrLJ12Vpkno-Q7WalmBTtB5TMnzDNL_yX84Ay49qnEiUXtSx0KK5I60ht2g",
    "appId": "https:\/\/example.okta.com",
    "version": "U2F_V2"
  },
  "_links": {
    "verify": {
      "href": "https:\/\/example.okta.com\/api\/v1\/authn\/factors\/fuf59d1ohqJZyOelX1t7\/verify",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}
`
