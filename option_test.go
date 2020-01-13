package warp

import (
	"errors"
	"reflect"
	"testing"
)

func TestTimeout(t *testing.T) {
	type optionTest struct {
		Name    string
		Timeout uint
		Options interface{}
		Err     error
	}

	tests := []optionTest{
		{
			Name:    "creation",
			Timeout: 30000,
			Options: &PublicKeyCredentialCreationOptions{},
		},
		{
			Name:    "request",
			Timeout: 30000,
			Options: &PublicKeyCredentialRequestOptions{},
		},
		{
			Name:    "bad",
			Timeout: 30000,
			Options: &CMCredential{},
			Err:     ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := Timeout(test.Timeout)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialCreationOptions:
				if options.Timeout != test.Timeout {
					tt.Fatalf("Unexpected value %d", options.Timeout)
				}
			case *PublicKeyCredentialRequestOptions:
				if options.Timeout != test.Timeout {
					tt.Fatalf("Unexpected value %d", options.Timeout)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestExtensions(t *testing.T) {
	type optionTest struct {
		Name       string
		Extensions []Extension
		Options    interface{}
		Expected   AuthenticationExtensionsClientInputs
		Err        error
	}

	tests := []optionTest{
		{
			Name: "creation",
			Extensions: []Extension{
				UseAppID("https://e3b0c442.io"),
			},
			Options: &PublicKeyCredentialCreationOptions{},
			Expected: AuthenticationExtensionsClientInputs{
				"appid": "https://e3b0c442.io",
			},
		},
		{
			Name: "request",
			Extensions: []Extension{
				UseAppID("https://e3b0c442.io"),
			},
			Options: &PublicKeyCredentialRequestOptions{},
			Expected: AuthenticationExtensionsClientInputs{
				"appid": "https://e3b0c442.io",
			},
		},
		{
			Name: "bad",
			Extensions: []Extension{
				UseAppID("https://e3b0c442.io"),
			},
			Options: &CMCredential{},
			Err:     ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := Extensions(test.Extensions...)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialCreationOptions:
				if !reflect.DeepEqual(options.Extensions, test.Expected) {
					tt.Fatalf("Unexpected value %d", options.Timeout)
				}
			case *PublicKeyCredentialRequestOptions:
				if !reflect.DeepEqual(options.Extensions, test.Expected) {
					tt.Fatalf("Unexpected value %d", options.Timeout)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestExcludeCredentials(t *testing.T) {
	type optionTest struct {
		Name        string
		Credentials []PublicKeyCredentialDescriptor
		Options     interface{}
		Err         error
	}

	tests := []optionTest{
		{
			Name: "creation",
			Credentials: []PublicKeyCredentialDescriptor{
				{
					Type: "public-key",
					ID:   []byte{0x1, 0x2, 0x3, 0x4},
				},
			},
			Options: &PublicKeyCredentialCreationOptions{},
		},
		{
			Name: "request",
			Credentials: []PublicKeyCredentialDescriptor{
				{
					Type: "public-key",
					ID:   []byte{0x1, 0x2, 0x3, 0x4},
				},
			},
			Options: &PublicKeyCredentialRequestOptions{},
			Err:     ErrOption,
		},
		{
			Name: "bad",
			Credentials: []PublicKeyCredentialDescriptor{
				{
					Type: "public-key",
					ID:   []byte{0x1, 0x2, 0x3, 0x4},
				},
			},
			Options: &CMCredential{},
			Err:     ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := ExcludeCredentials(test.Credentials)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialCreationOptions:
				if !reflect.DeepEqual(options.ExcludeCredentials, test.Credentials) {
					tt.Fatalf("Unexpected value %#v", options.ExcludeCredentials)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestAuthenticatorSelection(t *testing.T) {
	type optionTest struct {
		Name     string
		Criteria AuthenticatorSelectionCriteria
		Options  interface{}
		Err      error
	}

	tests := []optionTest{
		{
			Name: "creation",
			Criteria: AuthenticatorSelectionCriteria{
				AuthenticatorAttachment: AttachmentCrossPlatform,
			},
			Options: &PublicKeyCredentialCreationOptions{},
		},
		{
			Name: "request",
			Criteria: AuthenticatorSelectionCriteria{
				AuthenticatorAttachment: AttachmentCrossPlatform,
			},
			Options: &PublicKeyCredentialRequestOptions{},
			Err:     ErrOption,
		},
		{
			Name: "bad",
			Criteria: AuthenticatorSelectionCriteria{
				AuthenticatorAttachment: AttachmentCrossPlatform,
			},
			Options: &CMCredential{},
			Err:     ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := AuthenticatorSelection(test.Criteria)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialCreationOptions:
				if !reflect.DeepEqual(*options.AuthenticatorSelection, test.Criteria) {
					tt.Fatalf("Unexpected value %#v", options.AuthenticatorSelection)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestAttestation(t *testing.T) {
	type optionTest struct {
		Name       string
		Preference AttestationConveyancePreference
		Options    interface{}
		Err        error
	}

	tests := []optionTest{
		{
			Name:       "creation",
			Preference: ConveyanceDirect,
			Options:    &PublicKeyCredentialCreationOptions{},
		},
		{
			Name:       "request",
			Preference: ConveyanceDirect,
			Options:    &PublicKeyCredentialRequestOptions{},
			Err:        ErrOption,
		},
		{
			Name:       "bad",
			Preference: ConveyanceDirect,
			Options:    &CMCredential{},
			Err:        ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := Attestation(test.Preference)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialCreationOptions:
				if !reflect.DeepEqual(options.Attestation, test.Preference) {
					tt.Fatalf("Unexpected value %#v", options.Attestation)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestRelyingPartyID(t *testing.T) {
	type optionTest struct {
		Name    string
		RPID    string
		Options interface{}
		Err     error
	}

	tests := []optionTest{
		{
			Name:    "creation",
			RPID:    "e3b0c442.io",
			Options: &PublicKeyCredentialCreationOptions{},
			Err:     ErrOption,
		},
		{
			Name:    "request",
			RPID:    "e3b0c442.io",
			Options: &PublicKeyCredentialRequestOptions{},
		},
		{
			Name:    "bad",
			RPID:    "e3b0c442.io",
			Options: &CMCredential{},
			Err:     ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := RelyingPartyID(test.RPID)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialRequestOptions:
				if !reflect.DeepEqual(options.RPID, test.RPID) {
					tt.Fatalf("Unexpected value %#v", options.RPID)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestAllowCredentials(t *testing.T) {
	type optionTest struct {
		Name        string
		Credentials []PublicKeyCredentialDescriptor
		Options     interface{}
		Err         error
	}

	tests := []optionTest{
		{
			Name: "creation",
			Credentials: []PublicKeyCredentialDescriptor{
				{
					Type: "public-key",
					ID:   []byte{0x1, 0x2, 0x3, 0x4},
				},
			},
			Options: &PublicKeyCredentialCreationOptions{},
			Err:     ErrOption,
		},
		{
			Name: "request",
			Credentials: []PublicKeyCredentialDescriptor{
				{
					Type: "public-key",
					ID:   []byte{0x1, 0x2, 0x3, 0x4},
				},
			},
			Options: &PublicKeyCredentialRequestOptions{},
		},
		{
			Name: "bad",
			Credentials: []PublicKeyCredentialDescriptor{
				{
					Type: "public-key",
					ID:   []byte{0x1, 0x2, 0x3, 0x4},
				},
			},
			Options: &CMCredential{},
			Err:     ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := AllowCredentials(test.Credentials)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialRequestOptions:
				if !reflect.DeepEqual(options.AllowCredentials, test.Credentials) {
					tt.Fatalf("Unexpected value %#v", options.AllowCredentials)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}

func TestUserVerification(t *testing.T) {
	type optionTest struct {
		Name             string
		UserVerification UserVerificationRequirement
		Options          interface{}
		Err              error
	}

	tests := []optionTest{
		{
			Name:             "creation",
			UserVerification: VerificationDiscouraged,
			Options:          &PublicKeyCredentialCreationOptions{},
			Err:              ErrOption,
		},
		{
			Name:             "request",
			UserVerification: VerificationDiscouraged,
			Options:          &PublicKeyCredentialRequestOptions{},
		},
		{
			Name:             "bad",
			UserVerification: VerificationDiscouraged,
			Options:          &CMCredential{},
			Err:              ErrOption,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			opt := UserVerification(test.UserVerification)

			err := opt(test.Options)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			switch options := test.Options.(type) {
			case *PublicKeyCredentialRequestOptions:
				if !reflect.DeepEqual(options.UserVerification, test.UserVerification) {
					tt.Fatalf("Unexpected value %#v", options.UserVerification)
				}
			default:
				tt.Fatalf("Shouldn't be here")
			}
		})
	}
}
