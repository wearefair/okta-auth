package api

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/wearefair/okta-auth/factors"
)

func TestAuthenticationTransactionUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		input    string
		expected AuthenticationTransaction
	}{
		// MFA Required
		{
			input: sampleStateMFARequired,
			expected: AuthenticationTransaction{
				StateToken: "00CxTwYaT7vmrv2UShWT1KPhf4KLmeO5mspBg303rO",
				Status:     StateMFARequired,
				ExpiresAt:  time.Date(2017, 12, 12, 18, 48, 04, 0, time.UTC),
				Links: Links{
					Cancel: Link{
						HREF: "https://example.okta.com/api/v1/authn/cancel",
					},
				},
				Embedded: Embedded{
					User: User{
						Id: "00u2k4zip5XnaVacd1t6",
						Profile: UserProfile{
							Login:     "first@example.com",
							FirstName: "First",
							LastName:  "Last",
						},
					},
					Factors: []Factor{
						{
							Id:         "sms59eptnqQ7XZ2xe1t7",
							FactorType: factors.FactorTypeSMS,
							Provider:   "OKTA",
							Profile: FactorProfileSMS{
								PhoneNumber: "+1 XXX-XXX-5555",
							},
							Links: Links{
								Verify: Link{
									HREF: "https://example.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
								},
							},
						},
						{
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
						{
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
				},
			},
		},

		// MFA Challenge SMS
		{
			input: sampleStateMFAChallenge,
			expected: AuthenticationTransaction{
				StateToken: "00CxTwYaT7vmrv2UShWT1KPhf4KLmeO5mspBg303rO",
				Status:     StateMFAChallenge,
				ExpiresAt:  time.Date(2017, 12, 12, 18, 50, 13, 0, time.UTC),
				Links: Links{
					Next: Link{
						HREF: "https://example.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
					},
					Cancel: Link{
						HREF: "https://example.okta.com/api/v1/authn/cancel",
					},
					Prev: Link{
						HREF: "https://example.okta.com/api/v1/authn/previous",
					},
				},
				Embedded: Embedded{
					User: User{
						Id: "00u2k4zip5XnaVacd1t6",
						Profile: UserProfile{
							Login:     "first@example.com",
							FirstName: "First",
							LastName:  "Last",
						},
					},
					Factor: Factor{
						Id:         "sms59eptnqQ7XZ2xe1t7",
						FactorType: factors.FactorTypeSMS,
						Provider:   "OKTA",
						Profile: FactorProfileSMS{
							PhoneNumber: "+1 XXX-XXX-5555",
						},
					},
				},
			},
		},
	}

	for i, testCase := range testCases {
		actual := AuthenticationTransaction{}
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

// Grabbed from a real API response
var sampleStateMFARequired = `
{
  "stateToken": "00CxTwYaT7vmrv2UShWT1KPhf4KLmeO5mspBg303rO",
  "expiresAt": "2017-12-12T18:48:04.000Z",
  "status": "MFA_REQUIRED",
  "_embedded": {
    "user": {
      "id": "00u2k4zip5XnaVacd1t6",
      "passwordChanged": "2016-07-25T21:45:09.000Z",
      "profile": {
        "login": "first@example.com",
        "firstName": "First",
        "lastName": "Last",
        "locale": "en",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factors": [
      {
        "id": "sms59eptnqQ7XZ2xe1t7",
        "factorType": "sms",
        "provider": "OKTA",
        "vendorName": "OKTA",
        "profile": {
          "phoneNumber": "+1 XXX-XXX-5555"
        },
        "_links": {
          "verify": {
            "href": "https://example.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      },
      {
        "id": "fuf59d1ohqJZyOelX1t7",
        "factorType": "u2f",
        "provider": "FIDO",
        "vendorName": "FIDO",
        "profile": {
          "credentialId": "s94CdJnUd148p95PNq7AaY2Dv1QFrLJ12Vpkno-Q7WalmBTtB5TMnzDNL_yX84Ay49qnEiUXtSx0KK5I60ht2g",
          "appId": "https://example.okta.com",
          "version": "U2F_V2"
        },
        "_links": {
          "verify": {
            "href": "https://example.okta.com/api/v1/authn/factors/fuf59d1ohqJZyOelX1t7/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      },
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
            "href": "https://example.okta.com/api/v1/authn/factors/uftpep6vfeujtcuPc1t6/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      }
    ],
    "policy": {
      "allowRememberDevice": true,
      "rememberDeviceLifetimeInMinutes": 15,
      "rememberDeviceByDefault": false
    }
  },
  "_links": {
    "cancel": {
      "href": "https://example.okta.com/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}
`

// This is not used, just left for documentation of "reality"
var sampleStateMFAChallenge = `
{
  "stateToken": "00CxTwYaT7vmrv2UShWT1KPhf4KLmeO5mspBg303rO",
  "expiresAt": "2017-12-12T18:50:13.000Z",
  "status": "MFA_CHALLENGE",
  "_embedded": {
    "user": {
      "id": "00u2k4zip5XnaVacd1t6",
      "passwordChanged": "2016-07-25T21:45:09.000Z",
      "profile": {
        "login": "first@example.com",
        "firstName": "First",
        "lastName": "Last",
        "locale": "en",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factor": {
      "id": "sms59eptnqQ7XZ2xe1t7",
      "factorType": "sms",
      "provider": "OKTA",
      "vendorName": "OKTA",
      "profile": {
        "phoneNumber": "+1 XXX-XXX-5555"
      }
    },
    "policy": {
      "allowRememberDevice": true,
      "rememberDeviceLifetimeInMinutes": 15,
      "rememberDeviceByDefault": false
    }
  },
  "_links": {
    "next": {
      "name": "verify",
      "href": "https://example.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "cancel": {
      "href": "https://example.okta.com/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "prev": {
      "href": "https://example.okta.com/api/v1/authn/previous",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "resend": [
      {
        "name": "sms",
        "href": "https://example.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify/resend",
        "hints": {
          "allow": [
            "POST"
          ]
        }
      }
    ]
  }
}
`
