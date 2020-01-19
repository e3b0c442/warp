package warp

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

var mockPublicKeyCredentialRequestOptions = &PublicKeyCredentialRequestOptions{
	Challenge: []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	},
}

var mockRequestClientDataJSON []byte = []byte(`{"type":"webauthn.get","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`)

func TestStartAuthentication(t *testing.T) {
	type authTest struct {
		Name          string
		Opts          []Option
		AltRandReader io.Reader
		Expected      *PublicKeyCredentialRequestOptions
		Err           error
	}

	tests := []authTest{
		{
			Name:          "Bad rand reader",
			AltRandReader: &badReader{},
			Err:           ErrGenerateChallenge,
		},
		{
			Name: "Bad error option",
			Opts: []Option{errorOption()},
			Err:  ErrOption,
		},
		{
			Name: "Good no opts",
			Expected: &PublicKeyCredentialRequestOptions{
				Challenge: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
			},
		},
		{
			Name: "Good with opt",
			Opts: []Option{Timeout(30000)},
			Expected: &PublicKeyCredentialRequestOptions{
				Challenge: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				Timeout: 30000,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			oldRandReader := randReader
			if test.AltRandReader != nil {
				randReader = test.AltRandReader
			} else {
				randReader = &predictableReader{}
			}
			defer func() { randReader = oldRandReader }()

			opts, err := StartAuthentication(test.Opts...)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if !reflect.DeepEqual(opts, test.Expected) {
				tt.Fatalf("Output mismatch got %#v expected %#v", opts, test.Expected)
			}
		})
	}
}

func TestCheckAllowedCredentials(t *testing.T) {
	type checkTest struct {
		Name    string
		Allowed []PublicKeyCredentialDescriptor
		ID      []byte
		Err     error
	}

	tests := []checkTest{
		{
			Name:    "none allowed",
			Allowed: []PublicKeyCredentialDescriptor{},
		},
		{
			Name: "found allowed",
			Allowed: []PublicKeyCredentialDescriptor{
				{Type: "public-key", ID: []byte{0x1, 0x2, 0x3, 0x4}},
			},
			ID: []byte{0x1, 0x2, 0x3, 0x4},
		},
		{
			Name: "not found",
			Allowed: []PublicKeyCredentialDescriptor{
				{Type: "public-key", ID: []byte{0x1, 0x2, 0x3, 0x4}},
			},
			ID:  []byte{0x5, 0x6, 0x7, 0x8},
			Err: NewError("Credential ID not found in allowed list"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := checkAllowedCredentials(test.Allowed, test.ID)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
		})
	}
}

func errorUserFinder(_ []byte) (User, error) {
	return nil, ErrNotImplemented
}

func userFinderGenerator(u *testUser) UserFinder {
	return func(_ []byte) (User, error) {
		return u, nil
	}
}

func TestGetUserVerifiedCredential(t *testing.T) {
	type getTest struct {
		Name     string
		Finder   UserFinder
		Cred     *AssertionPublicKeyCredential
		Expected Credential
		Err      error
	}

	tests := []getTest{
		{
			Name:   "finder error",
			Finder: errorUserFinder,
			Cred: &AssertionPublicKeyCredential{
				Response: AuthenticatorAssertionResponse{
					UserHandle: []byte{},
				},
			},
			Err: ErrNotImplemented,
		},
		{
			Name:   "No credential",
			Finder: userFinderGenerator(mockUser),
			Cred: &AssertionPublicKeyCredential{
				Response: AuthenticatorAssertionResponse{
					UserHandle: []byte{},
				},
			},
			Err: NewError("User jsmith does not own this credential"),
		},
		{
			Name: "Good",
			Finder: userFinderGenerator(&testUser{
				credentials: map[string]Credential{
					"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU": &testCred{},
				},
			}),
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
					},
				},
				Response: AuthenticatorAssertionResponse{
					UserHandle: []byte{},
				},
			},
			Expected: &testCred{},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			u, err := getUserVerifiedCredential(test.Finder, test.Cred)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpecetd error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if !reflect.DeepEqual(u, test.Expected) {
				tt.Fatalf("Output mismatch got %#v expected %#v", u, test.Expected)
			}
		})
	}
}

func TestFinishAuthentication(t *testing.T) {
	type authTest struct {
		Name       string
		RP         RelyingParty
		UserFinder UserFinder
		Opts       *PublicKeyCredentialRequestOptions
		Cred       *AssertionPublicKeyCredential
		Expected   uint
		Err        error
	}

	tests := []authTest{
		{
			Name: "disallowed credential",
			Opts: &PublicKeyCredentialRequestOptions{
				AllowCredentials: []PublicKeyCredentialDescriptor{
					{Type: "public-key", ID: []byte{0x1, 0x2, 0x3, 0x4}},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					RawID: []byte{0x5, 0x6, 0x7, 0x8},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "no credential",
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred:       &AssertionPublicKeyCredential{},
			UserFinder: errorUserFinder,
			Err:        ErrVerifyAuthentication,
		},
		{
			Name:       "bad authenticator data",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: []byte{},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad client data",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte("<"),
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad C.type",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.bad","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad challenge",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"vU-emL62jG6tMkOxtMf-11-k_qqx-EeVy9iphnaio3U","origin":"https://e3b0c442.io"}`),
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad origin",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://bad.origin"}`),
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad token binding",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io","tokenBinding":{"status":"present"}}`),
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad rpID hash",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: []byte{
						0xd9, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x41,                   // authData.Flags
						0x00, 0x00, 0x00, 0x00, // authData.SignCount
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // authData.attestedCredentialData.aaguid
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // v
						0x00, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
						0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, // authData.attestedCredentialData.credentialID
						0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, // |
						0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, // |
						0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, // v
						0xa5, // map of 5 items
						0x1,  // key 1 (Kty)
						0x2,  // 2 (EC2 key)
						0x3,  // key 3 (Alg)
						0x26, // -7
						0x20, // key -1
						0x1,  // 1 (P256 Curve)
						0x21, // key -2
						0x58, // byte string, >24 bytes
						0x20, // 32 bytes length
						0x36, 0xc4, 0x85, 0xf8, 0x83, 0xda, 0xcf, 0xb3,
						0x63, 0xc8, 0xf6, 0x4d, 0x6a, 0x82, 0xe5, 0x65,
						0x3d, 0x7d, 0x36, 0x64, 0x2b, 0x3a, 0x10, 0x8b,
						0x51, 0x55, 0x5a, 0x8d, 0x33, 0x40, 0x7d, 0x5c,
						0x22, // key -3
						0x58, // byte string, >24 bytes
						0x20, // 32 bytes length
						0x69, 0xc9, 0x52, 0x21, 0x4f, 0xce, 0x43, 0xea,
						0x5f, 0x80, 0x43, 0x10, 0xbb, 0xe6, 0x3e, 0xd,
						0xee, 0xcb, 0xf1, 0xe9, 0xba, 0x69, 0x5d, 0xac,
						0x77, 0x53, 0xb1, 0x31, 0xbc, 0xbf, 0xf3, 0x98,
					},
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "user present missing",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: []byte{
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x40,                   // authData.Flags
						0x00, 0x00, 0x00, 0x00, // authData.SignCount
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // authData.attestedCredentialData.aaguid
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // v
						0x00, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
						0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, // authData.attestedCredentialData.credentialID
						0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, // |
						0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, // |
						0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, // v
						0xa5, // map of 5 items
						0x1,  // key 1 (Kty)
						0x2,  // 2 (EC2 key)
						0x3,  // key 3 (Alg)
						0x26, // -7
						0x20, // key -1
						0x1,  // 1 (P256 Curve)
						0x21, // key -2
						0x58, // byte string, >24 bytes
						0x20, // 32 bytes length
						0x36, 0xc4, 0x85, 0xf8, 0x83, 0xda, 0xcf, 0xb3,
						0x63, 0xc8, 0xf6, 0x4d, 0x6a, 0x82, 0xe5, 0x65,
						0x3d, 0x7d, 0x36, 0x64, 0x2b, 0x3a, 0x10, 0x8b,
						0x51, 0x55, 0x5a, 0x8d, 0x33, 0x40, 0x7d, 0x5c,
						0x22, // key -3
						0x58, // byte string, >24 bytes
						0x20, // 32 bytes length
						0x69, 0xc9, 0x52, 0x21, 0x4f, 0xce, 0x43, 0xea,
						0x5f, 0x80, 0x43, 0x10, 0xbb, 0xe6, 0x3e, 0xd,
						0xee, 0xcb, 0xf1, 0xe9, 0xba, 0x69, 0x5d, 0xac,
						0x77, 0x53, 0xb1, 0x31, 0xbc, 0xbf, 0xf3, 0x98,
					},
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad user verification",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts: &PublicKeyCredentialRequestOptions{
				Challenge: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				UserVerification: VerificationRequired,
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: []byte{
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x41,                   // authData.Flags
						0x00, 0x00, 0x00, 0x00, // authData.SignCount
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // authData.attestedCredentialData.aaguid
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // v
						0x00, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
						0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, // authData.attestedCredentialData.credentialID
						0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, // |
						0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, // |
						0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, // v
						0xa5, // map of 5 items
						0x1,  // key 1 (Kty)
						0x2,  // 2 (EC2 key)
						0x3,  // key 3 (Alg)
						0x26, // -7
						0x20, // key -1
						0x1,  // 1 (P256 Curve)
						0x21, // key -2
						0x58, // byte string, >24 bytes
						0x20, // 32 bytes length
						0x36, 0xc4, 0x85, 0xf8, 0x83, 0xda, 0xcf, 0xb3,
						0x63, 0xc8, 0xf6, 0x4d, 0x6a, 0x82, 0xe5, 0x65,
						0x3d, 0x7d, 0x36, 0x64, 0x2b, 0x3a, 0x10, 0x8b,
						0x51, 0x55, 0x5a, 0x8d, 0x33, 0x40, 0x7d, 0x5c,
						0x22, // key -3
						0x58, // byte string, >24 bytes
						0x20, // 32 bytes length
						0x69, 0xc9, 0x52, 0x21, 0x4f, 0xce, 0x43, 0xea,
						0x5f, 0x80, 0x43, 0x10, 0xbb, 0xe6, 0x3e, 0xd,
						0xee, 0xcb, 0xf1, 0xe9, 0xba, 0x69, 0x5d, 0xac,
						0x77, 0x53, 0xb1, 0x31, 0xbc, 0xbf, 0xf3, 0x98,
					},
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad extensions",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "bad signature",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					Signature: []byte{
						0x30, 0x46, 0x2, 0x21, 0x0, 0xba, 0xcb, 0x7,
						0x38, 0xec, 0x5f, 0x5b, 0xdf, 0x7b, 0xbf, 0x71,
						0x30, 0x2f, 0x50, 0x32, 0x45, 0x4a, 0xe1, 0x39,
						0x7c, 0x1c, 0xbb, 0xce, 0xec, 0xa6, 0x66, 0x29,
						0x8, 0x6b, 0x83, 0xc4, 0xd1, 0x2, 0x21, 0x0,
						0xb8, 0x3, 0x9f, 0xff, 0xff, 0x30, 0xd5, 0x73,
						0x1e, 0x9c, 0xae, 0xad, 0x7d, 0xb7, 0xb2, 0xe1,
						0x6, 0x39, 0x54, 0xb7, 0x46, 0xeb, 0xf, 0x81,
						0x4d, 0xa, 0x5e, 0xa, 0x11, 0xd1, 0x82, 0xd1,
					},
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name: "bad signcount",
			RP:   mockRP,
			UserFinder: userFinderGenerator(&testUser{
				name: "jsmith",
				icon: "",
				id: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				displayName: "John Smith",
				credentials: map[string]Credential{
					mockCredentialID: &testCred{
						owner:     nil,
						id:        mockRawCredentialID,
						publicKey: []byte(cborPublicKey),
						signCount: 2,
					},
				},
			}),
			Opts: mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					Signature: []byte{
						0x30, 0x44, 0x2, 0x20, 0x3d, 0xb1, 0xab, 0x5e,
						0xb8, 0x1e, 0x1d, 0xf0, 0x63, 0xf, 0xc5, 0x72,
						0xd2, 0x23, 0x6f, 0xad, 0xa3, 0x57, 0x27, 0xc6,
						0x7, 0xaa, 0xd0, 0x56, 0x50, 0xe6, 0x84, 0x8f,
						0xf6, 0x9e, 0xc2, 0xe2, 0x2, 0x20, 0x5d, 0x8c,
						0x8f, 0xf0, 0xab, 0x69, 0xa9, 0x32, 0xc6, 0x79,
						0x5e, 0x2, 0x7e, 0x28, 0x81, 0x58, 0xc8, 0xd,
						0x8b, 0x59, 0x28, 0xd2, 0x2d, 0x52, 0xa2, 0x82,
						0x78, 0x95, 0x9, 0xc3, 0xe3, 0x3b,
					},
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name:       "good signcount",
			RP:         mockRP,
			UserFinder: userFinderGenerator(mockUser),
			Opts:       mockPublicKeyCredentialRequestOptions,
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: mockCredentialID,
					},
				},
				Response: AuthenticatorAssertionResponse{
					AuthenticatorData: mockRawAuthData,
					Signature: []byte{
						0x30, 0x44, 0x2, 0x20, 0x3d, 0xb1, 0xab, 0x5e,
						0xb8, 0x1e, 0x1d, 0xf0, 0x63, 0xf, 0xc5, 0x72,
						0xd2, 0x23, 0x6f, 0xad, 0xa3, 0x57, 0x27, 0xc6,
						0x7, 0xaa, 0xd0, 0x56, 0x50, 0xe6, 0x84, 0x8f,
						0xf6, 0x9e, 0xc2, 0xe2, 0x2, 0x20, 0x5d, 0x8c,
						0x8f, 0xf0, 0xab, 0x69, 0xa9, 0x32, 0xc6, 0x79,
						0x5e, 0x2, 0x7e, 0x28, 0x81, 0x58, 0xc8, 0xd,
						0x8b, 0x59, 0x28, 0xd2, 0x2d, 0x52, 0xa2, 0x82,
						0x78, 0x95, 0x9, 0xc3, 0xe3, 0x3b,
					},
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockRequestClientDataJSON,
					},
				},
			},
			Expected: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			out, err := FinishAuthentication(test.RP, test.UserFinder, test.Opts, test.Cred)
			if err != nil {
				if errors.Is(err, test.Err) {
					for err != nil {
						tt.Log(err)
						err = errors.Unwrap(err)
					}
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if out != test.Expected {
				tt.Fatalf("Unexpected signCount %d", out)
			}
		})
	}
}
