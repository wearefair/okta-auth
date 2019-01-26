package okta

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestFactorSorting(t *testing.T) {
	factors := Factors{
		Factor{FactorType: FactorTypePush},
		Factor{FactorType: FactorTypeSMS},
		Factor{FactorType: FactorTypeCall},
		Factor{FactorType: FactorTypeU2F},
		Factor{FactorType: FactorTypeToken},
		Factor{FactorType: FactorTypeTokenSoftwareTOTP},
		Factor{FactorType: FactorType("unknown2")},
		Factor{FactorType: FactorTypeTokenHardware},
		Factor{FactorType: FactorTypeQuestion},
		Factor{FactorType: FactorType("unknown1")},
	}

	expected := Factors{
		Factor{FactorType: FactorTypeU2F},
		Factor{FactorType: FactorTypeToken},
		Factor{FactorType: FactorTypeTokenSoftwareTOTP},
		Factor{FactorType: FactorTypeTokenHardware},
		Factor{FactorType: FactorTypePush},
		Factor{FactorType: FactorTypeSMS},
		Factor{FactorType: FactorTypeCall},
		Factor{FactorType: FactorTypeQuestion},
		Factor{FactorType: FactorType("unknown1")},
		Factor{FactorType: FactorType("unknown2")},
	}

	sort.Sort(factors)

	for i, expected := range expected {
		if factors[i].FactorType != expected.FactorType {
			t.Errorf("%0d: expected %s but got %s", i, expected.FactorType, factors[i].FactorType)
		}
	}
}

func TestFactorUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		input    string
		expected Factor
	}{
		{
			input: sampleTokenFactor,
			expected: Factor{
				Id:         "uftpep6vfeujtcuPc1t6",
				FactorType: FactorTypeTokenSoftwareTOTP,
				Provider:   "GOOGLE",
				Profile: FactorProfileToken{
					CredentialId: "marshallb@fair.com",
				},
				Links: Links{
					Verify: Link{
						HREF: "https://fair.okta.com/api/v1/authn/factors/uftpep6vfeujtcuPc1t6/verify",
					},
				},
			},
		},
		{
			input: sampleU2FFactor,
			expected: Factor{
				Id:         "fuf59d1ohqJZyOelX1t7",
				FactorType: FactorTypeU2F,
				Provider:   "FIDO",
				Profile: FactorProfileU2F{
					CredentialId: "s94CdJnUd148p95PNq7AaY2Dv1QFrLJ12Vpkno-Q7WalmBTtB5TMnzDNL_yX84Ay49qnEiUXtSx0KK5I60ht2g",
					AppId:        "https://fair.okta.com",
					Version:      "U2F_V2",
				},
				Links: Links{
					Verify: Link{
						HREF: "https://fair.okta.com/api/v1/authn/factors/fuf59d1ohqJZyOelX1t7/verify",
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
    "credentialId": "marshallb@fair.com"
  },
  "_links": {
    "verify": {
      "href": "https:\/\/fair.okta.com\/api\/v1\/authn\/factors\/uftpep6vfeujtcuPc1t6\/verify",
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
    "appId": "https:\/\/fair.okta.com",
    "version": "U2F_V2"
  },
  "_links": {
    "verify": {
      "href": "https:\/\/fair.okta.com\/api\/v1\/authn\/factors\/fuf59d1ohqJZyOelX1t7\/verify",
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
        "login": "marshallb@fair.com",
        "firstName": "Marshall",
        "lastName": "Brekka",
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
          "phoneNumber": "+1 XXX-XXX-5260"
        },
        "_links": {
          "verify": {
            "href": "https://fair.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
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
          "appId": "https://fair.okta.com",
          "version": "U2F_V2"
        },
        "_links": {
          "verify": {
            "href": "https://fair.okta.com/api/v1/authn/factors/fuf59d1ohqJZyOelX1t7/verify",
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
          "credentialId": "marshallb@fair.com"
        },
        "_links": {
          "verify": {
            "href": "https://fair.okta.com/api/v1/authn/factors/uftpep6vfeujtcuPc1t6/verify",
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
      "href": "https://fair.okta.com/api/v1/authn/cancel",
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
        "login": "marshallb@fair.com",
        "firstName": "Marshall",
        "lastName": "Brekka",
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
        "phoneNumber": "+1 XXX-XXX-5260"
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
      "href": "https://fair.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "cancel": {
      "href": "https://fair.okta.com/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "prev": {
      "href": "https://fair.okta.com/api/v1/authn/previous",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "resend": [
      {
        "name": "sms",
        "href": "https://fair.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify/resend",
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

// This is not used, just left for documentation of "reality"
var sampleStateMFAChallengeSMS = `
{
  "stateToken": "00_h3SNDbA6Y5aWPBkq6HUPDXWMQk8G4jT4-L-J9CF",
  "expiresAt": "2017-12-13T20:42:20.000Z",
  "status": "MFA_CHALLENGE",
  "_embedded": {
    "user": {
      "id": "00u2k4zip5XnaVacd1t6",
      "passwordChanged": "2016-07-25T21:45:09.000Z",
      "profile": {
        "login": "marshallb@fair.com",
        "firstName": "Marshall",
        "lastName": "Brekka",
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
        "phoneNumber": "+1 XXX-XXX-5260"
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
      "href": "https://fair.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "cancel": {
      "href": "https://fair.okta.com/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "prev": {
      "href": "https://fair.okta.com/api/v1/authn/previous",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "resend": [
      {
        "name": "sms",
        "href": "https://fair.okta.com/api/v1/authn/factors/sms59eptnqQ7XZ2xe1t7/verify/resend",
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
