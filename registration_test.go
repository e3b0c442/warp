package warp

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type testRP struct {
	id     string
	name   string
	icon   string
	origin string
}

func (rp *testRP) EntityID() string {
	return rp.id
}

func (rp *testRP) EntityName() string {
	return rp.name
}

func (rp *testRP) EntityIcon() string {
	return rp.icon
}

func (rp *testRP) Origin() string {
	return rp.origin
}

type testUser struct {
	name        string
	icon        string
	id          []byte
	displayName string
	credentials map[string]Credential
}

func (u *testUser) EntityName() string {
	return u.name
}

func (u *testUser) EntityIcon() string {
	return u.icon
}

func (u *testUser) EntityID() []byte {
	return u.id
}

func (u *testUser) EntityDisplayName() string {
	return u.displayName
}

func (u *testUser) Credentials() map[string]Credential {
	return u.credentials
}

type testCred struct {
	owner     User
	id        []byte
	publicKey []byte
	signCount uint
}

func (c *testCred) Owner() User {
	return c.owner
}

func (c *testCred) CredentialID() []byte {
	return c.id
}

func (c *testCred) CredentialPublicKey() []byte {
	return c.publicKey
}

func (c *testCred) CredentialSignCount() uint {
	return c.signCount
}

var mockRP *testRP = &testRP{
	id:     "e3b0c442.io",
	name:   "e3b0c442.io",
	icon:   "",
	origin: "https://e3b0c442.io",
}

var mockPublicKeyCredentialCreationOptions = &PublicKeyCredentialCreationOptions{
	RP: PublicKeyCredentialRPEntity{
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: "e3b0c442.io",
			Icon: "",
		},
		ID: "e3b0c442.io",
	},
	User: PublicKeyCredentialUserEntity{
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: "jsmith",
			Icon: "",
		},
		ID: []byte{
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
		DisplayName: "John Smith",
	},
	Challenge: []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	},
	PubKeyCredParams: []PublicKeyCredentialParameters{
		{
			Type: "public-key",
			Alg:  -8,
		},
		{
			Type: "public-key",
			Alg:  -36,
		},
		{
			Type: "public-key",
			Alg:  -35,
		},
		{
			Type: "public-key",
			Alg:  -7,
		},
		{
			Type: "public-key",
			Alg:  -39,
		},
		{
			Type: "public-key",
			Alg:  -38,
		},
		{
			Type: "public-key",
			Alg:  -37,
		},
		{
			Type: "public-key",
			Alg:  -259,
		},
		{
			Type: "public-key",
			Alg:  -258,
		},
		{
			Type: "public-key",
			Alg:  -257,
		},
		{
			Type: "public-key",
			Alg:  -65535,
		},
	},
}

func errorOption() Option {
	return func(_ interface{}) error {
		return ErrOption
	}
}

func errorCredFinder(_ []byte) (Credential, error) {
	return nil, NewError("Not found")
}

func foundCredFinder(id []byte) (Credential, error) {

	return &testCred{
		owner:     mockUser,
		id:        id,
		publicKey: []byte{},
		signCount: 0,
	}, nil
}

func TestSupportedPublicKeyCredentialParameters(t *testing.T) {
	params := SupportedPublicKeyCredentialParameters()
	if !reflect.DeepEqual(params, []PublicKeyCredentialParameters{
		{
			Type: "public-key",
			Alg:  -8,
		},
		{
			Type: "public-key",
			Alg:  -36,
		},
		{
			Type: "public-key",
			Alg:  -35,
		},
		{
			Type: "public-key",
			Alg:  -7,
		},
		{
			Type: "public-key",
			Alg:  -39,
		},
		{
			Type: "public-key",
			Alg:  -38,
		},
		{
			Type: "public-key",
			Alg:  -37,
		},
		{
			Type: "public-key",
			Alg:  -259,
		},
		{
			Type: "public-key",
			Alg:  -258,
		},
		{
			Type: "public-key",
			Alg:  -257,
		},
		{
			Type: "public-key",
			Alg:  -65535,
		},
	}) {
		t.Fatalf("Params list mismatch")
	}
}

func TestStartRegistration(t *testing.T) {
	type registrationTest struct {
		Name          string
		RP            RelyingParty
		User          User
		Opts          []Option
		AltRandReader io.Reader
		Expected      *PublicKeyCredentialCreationOptions
		Err           error
	}

	tests := []registrationTest{
		{
			Name:          "Bad rand reader",
			RP:            &testRP{},
			User:          &testUser{},
			AltRandReader: &badReader{},
			Err:           ErrGenerateChallenge,
		},
		{
			Name: "Bad option",
			RP:   &testRP{},
			User: &testUser{},
			Opts: []Option{errorOption()},
			Err:  ErrOption,
		},
		{
			Name:     "Good no options",
			RP:       mockRP,
			User:     mockUser,
			Expected: mockPublicKeyCredentialCreationOptions,
		},
		{
			Name: "good with opt",
			RP: &testRP{
				id:     "e3b0c442.io",
				name:   "e3b0c442.io",
				icon:   "",
				origin: "https://e3b0c442.io",
			},
			User: &testUser{
				name: "jsmith",
				icon: "",
				id: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				displayName: "John Smith",
				credentials: map[string]Credential{},
			},
			Opts: []Option{
				Timeout(30000),
			},
			Expected: &PublicKeyCredentialCreationOptions{
				RP: PublicKeyCredentialRPEntity{
					PublicKeyCredentialEntity: PublicKeyCredentialEntity{
						Name: "e3b0c442.io",
						Icon: "",
					},
					ID: "e3b0c442.io",
				},
				User: PublicKeyCredentialUserEntity{
					PublicKeyCredentialEntity: PublicKeyCredentialEntity{
						Name: "jsmith",
						Icon: "",
					},
					ID: []byte{
						0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
						0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
						0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
						0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
					},
					DisplayName: "John Smith",
				},
				Challenge: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				PubKeyCredParams: []PublicKeyCredentialParameters{
					{
						Type: "public-key",
						Alg:  -8,
					},
					{
						Type: "public-key",
						Alg:  -36,
					},
					{
						Type: "public-key",
						Alg:  -35,
					},
					{
						Type: "public-key",
						Alg:  -7,
					},
					{
						Type: "public-key",
						Alg:  -39,
					},
					{
						Type: "public-key",
						Alg:  -38,
					},
					{
						Type: "public-key",
						Alg:  -37,
					},
					{
						Type: "public-key",
						Alg:  -259,
					},
					{
						Type: "public-key",
						Alg:  -258,
					},
					{
						Type: "public-key",
						Alg:  -257,
					},
					{
						Type: "public-key",
						Alg:  -65535,
					},
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

			opts, err := StartRegistration(test.RP, test.User, test.Opts...)
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
				tt.Fatalf("Output mismatch: got %#v expected %#v", opts, test.Expected)
			}
		})
	}
}

func TestDecodeAttestationObject(t *testing.T) {
	type decodeTest struct {
		Name     string
		Cred     *AttestationPublicKeyCredential
		AuthData AuthenticatorData
		Fmt      AttestationStatementFormat
		AttStmt  cbor.RawMessage
		Err      bool
	}

	tests := []decodeTest{
		{
			Name: "bad",
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AttestationObject: []byte{0x43, 0x00},
				},
			},
			Err: true,
		},
		{
			Name: "good",
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AttestationObject: mockRawNoneAttestationObject,
				},
			},
			AuthData: mockAuthData,
			Fmt:      AttestationFormatNone,
			AttStmt:  []byte{0xa0},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {

			attestation, err := decodeAttestationObject(test.Cred)
			if err != nil {
				if test.Err {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err {
				tt.Fatalf("Did not get expected error")
			}
			if !reflect.DeepEqual(attestation.AuthData, test.AuthData) {
				tt.Fatalf("AuthData mismatch got %#v expected %#v", attestation.AuthData, test.AuthData)
			}
			if attestation.Fmt != test.Fmt {
				tt.Fatalf("Fmt mismatch got %s expected %s", attestation.Fmt, test.Fmt)
			}
			if !bytes.Equal(attestation.AttStmt, test.AttStmt) {
				tt.Fatalf("AttStmt mismatch got %#v expected %#v", attestation.AttStmt, test.AttStmt)
			}
		})
	}
}

func TestVerifyAttestationStatement(t *testing.T) {
	type verifyTest struct {
		Name           string
		Attestation    *AttestationObject
		ClientDataHash [32]byte
		Err            error
	}

	tests := []verifyTest{
		{
			Name: "bad",
			Attestation: &AttestationObject{
				Fmt: "wrong",
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name: "good none",
			Attestation: &AttestationObject{
				Fmt:      "none",
				AttStmt:  cbor.RawMessage{0xa0},
				AuthData: mockAuthData,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyAttestationStatement(test.Attestation, test.ClientDataHash)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
		})
	}
}

func TestFinishRegistration(t *testing.T) {

	type registrationTest struct {
		Name       string
		RP         RelyingParty
		CredFinder CredentialFinder
		Opts       *PublicKeyCredentialCreationOptions
		Cred       *AttestationPublicKeyCredential
		Vals       []RegistrationValidator
		Err        error
	}

	tests := []registrationTest{
		{
			Name: "bad provided validator",
			Vals: []RegistrationValidator{
				func(*PublicKeyCredentialCreationOptions, *AttestationPublicKeyCredential) error {
					return errors.New("err")
				},
			},
			Err: ErrVerifyAuthentication,
		},
		{
			Name: "bad client data parse",
			RP:   mockRP,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte("<"),
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad C.type",
			RP:   mockRP,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.bad","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad challenge",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"vU-emL62jG6tMkOxtMf-11-k_qqx-EeVy9iphnaio3U","origin":"https://e3b0c442.io"}`),
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad origin",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"bad.origin"}`),
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad token binding",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io","tokenBinding":{"status":"present"}}`),
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad attestation object",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{0x43, 0x00},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad authenticator data",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x65, // "none"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0xa0,                                           // null
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, // authData.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x40,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad rpID hash",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x65, // "none"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0xa0,                                           // null
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, // authData.rpIDHash
						0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, // |
						0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, // |
						0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, // v
						0x00,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "user present not set",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x65, // "none"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0xa0,                                           // null
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, // authData.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x00,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "user verification not set when required",
			RP:   mockRP,
			Opts: &PublicKeyCredentialCreationOptions{
				RP: PublicKeyCredentialRPEntity{
					PublicKeyCredentialEntity: PublicKeyCredentialEntity{
						Name: "e3b0c442.io",
						Icon: "",
					},
					ID: "e3b0c442.io",
				},
				User: PublicKeyCredentialUserEntity{
					PublicKeyCredentialEntity: PublicKeyCredentialEntity{
						Name: "jsmith",
						Icon: "",
					},
					ID: []byte{
						0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
						0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
						0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
						0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
					},
					DisplayName: "John Smith",
				},
				Challenge: []byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				PubKeyCredParams: []PublicKeyCredentialParameters{
					{
						Type: "public-key",
						Alg:  -8,
					},
					{
						Type: "public-key",
						Alg:  -36,
					},
					{
						Type: "public-key",
						Alg:  -35,
					},
					{
						Type: "public-key",
						Alg:  -7,
					},
					{
						Type: "public-key",
						Alg:  -39,
					},
					{
						Type: "public-key",
						Alg:  -38,
					},
					{
						Type: "public-key",
						Alg:  -37,
					},
					{
						Type: "public-key",
						Alg:  -259,
					},
					{
						Type: "public-key",
						Alg:  -258,
					},
					{
						Type: "public-key",
						Alg:  -257,
					},
					{
						Type: "public-key",
						Alg:  -65535,
					},
				},
				AuthenticatorSelection: &AuthenticatorSelectionCriteria{
					UserVerification: VerificationRequired,
				},
			},
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x65, // "none"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0xa0,                                           // null
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, // authData.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x01,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "user verification not set when required",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x65, // "none"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0xa0,                                           // null
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, // authData.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x01,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad attestation format",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x66, // "nonf"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0xa0,                                           // null
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, // authData.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x01,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name: "bad attestation statement",
			RP:   mockRP,
			Opts: mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: []byte{
						0xa3,             // map, 3 items
						0x63,             // text string, 3 chars
						0x66, 0x6d, 0x74, // "fmt"
						0x64,                   // text string, 4 chars
						0x6e, 0x6f, 0x6e, 0x65, // "none"
						0x67,                                     // text string, 7 chars
						0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
						0x00,                                           // 0
						0x68,                                           // text string, 8 chars
						0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
						0x58, 0x25, // byte string, 37 chars
						0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, // authData.rpIDHash
						0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
						0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
						0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
						0x01,                   // authData.flags
						0x00, 0x00, 0x00, 0x00, // authData.signCount
					},
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name:       "credfinder error",
			RP:         mockRP,
			CredFinder: foundCredFinder,
			Opts:       mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: mockRawNoneAttestationObject,
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name:       "good none attestation",
			RP:         mockRP,
			CredFinder: errorCredFinder,
			Opts:       mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
					},
				},
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockCreateClientDataJSON,
					},
					AttestationObject: mockRawNoneAttestationObject,
				},
			},
		},
		{
			Name:       "good fido-u2f attestation",
			RP:         mockRP,
			CredFinder: errorCredFinder,
			Opts:       mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
					},
				},
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockCreateClientDataJSON,
					},
					AttestationObject: mockRawFIDOU2FAttestationObject,
				},
			},
		},
		{
			Name:       "good packed attestation",
			RP:         mockRP,
			CredFinder: errorCredFinder,
			Opts:       mockPublicKeyCredentialCreationOptions,
			Cred: &AttestationPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					CMCredential: CMCredential{
						ID: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
					},
				},
				Response: AuthenticatorAttestationResponse{
					AuthenticatorResponse: AuthenticatorResponse{
						ClientDataJSON: mockCreateClientDataJSON,
					},
					AttestationObject: mockRawPackedAttestationObject,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			att, err := FinishRegistration(test.RP, test.CredFinder, test.Opts, test.Cred, test.Vals...)
			if err != nil {
				err2 := err
				for err2 != nil {
					tt.Log(err2)
					err2 = errors.Unwrap(err2)
				}
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not receive expected error")
			}

			passedAttObj := AttestationObject{}
			err = passedAttObj.UnmarshalBinary(test.Cred.Response.AttestationObject)
			if err != nil {
				tt.Fatal("Unable to parse passed attestation object")
			}
			if !reflect.DeepEqual(&passedAttObj, att) {
				tt.Fatalf("Output mismatch, got %#v expected %#v", *att, passedAttObj)
			}

		})
	}
}
