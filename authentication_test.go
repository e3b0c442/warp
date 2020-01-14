package warp

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

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
