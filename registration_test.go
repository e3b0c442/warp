package warp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor"
)

type testRP struct {
	id     string
	name   string
	icon   string
	origin string
}

func (rp *testRP) ID() string {
	return rp.id
}

func (rp *testRP) Name() string {
	return rp.name
}

func (rp *testRP) Icon() string {
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

func (u *testUser) Name() string {
	return u.name
}

func (u *testUser) Icon() string {
	return u.icon
}

func (u *testUser) ID() []byte {
	return u.id
}

func (u *testUser) DisplayName() string {
	return u.displayName
}

func (u *testUser) Credentials() map[string]Credential {
	return u.credentials
}

type testCred struct {
	user      User
	id        string
	publicKey []byte
	signCount uint
}

func (c *testCred) User() User {
	return c.user
}

func (c *testCred) ID() string {
	return c.id
}

func (c *testCred) PublicKey() []byte {
	return c.publicKey
}

func (c *testCred) SignCount() uint {
	return c.signCount
}

var mockRP *testRP = &testRP{
	id:     "e3b0c442.io",
	name:   "e3b0c442.io",
	icon:   "",
	origin: "https://e3b0c442.io",
}

var mockUser *testUser = &testUser{
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
}

var mockClientDataJSON []byte = []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`)

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

var mockRawAuthData []byte = []byte{
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
}

var mockAttestationObject AttestationObject = AttestationObject{
	AuthData: mockRawAuthData,
	Fmt:      AttestationFormatNone,
	AttStmt:  cbor.RawMessage{0xa0},
}

var mockRawAttestationObject cbor.RawMessage = cbor.RawMessage{
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
	0x58, 0xa4, // byte string, 164 chars
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
}

type predictableReader struct{}

func (predictableReader) Read(p []byte) (n int, err error) {
	b := bytes.NewBuffer(
		[]byte{
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
	)

	return b.Read(p)
}

var rawCredentialPrivateKey []byte = []byte{
	0x30, 0x77, 0x2, 0x1, 0x1, 0x4, 0x20, 0x3c,
	0x3, 0xfb, 0xd2, 0x8, 0x96, 0x79, 0x45, 0x6e,
	0xba, 0x1f, 0x5f, 0x31, 0x8c, 0x87, 0xf6, 0x5c,
	0x2, 0xa4, 0x95, 0xb3, 0xa2, 0xab, 0xb5, 0x47,
	0x2, 0x19, 0x51, 0x4e, 0x3b, 0x66, 0xf1, 0xa0,
	0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d,
	0x3, 0x1, 0x7, 0xa1, 0x44, 0x3, 0x42, 0x0,
	0x4, 0x36, 0xc4, 0x85, 0xf8, 0x83, 0xda, 0xcf,
	0xb3, 0x63, 0xc8, 0xf6, 0x4d, 0x6a, 0x82, 0xe5,
	0x65, 0x3d, 0x7d, 0x36, 0x64, 0x2b, 0x3a, 0x10,
	0x8b, 0x51, 0x55, 0x5a, 0x8d, 0x33, 0x40, 0x7d,
	0x5c, 0x69, 0xc9, 0x52, 0x21, 0x4f, 0xce, 0x43,
	0xea, 0x5f, 0x80, 0x43, 0x10, 0xbb, 0xe6, 0x3e,
	0xd, 0xee, 0xcb, 0xf1, 0xe9, 0xba, 0x69, 0x5d,
	0xac, 0x77, 0x53, 0xb1, 0x31, 0xbc, 0xbf, 0xf3,
	0x98,
}

var cborPublicKey cbor.RawMessage = cbor.RawMessage{
	0xa5, 0x1, 0x2, 0x3, 0x26, 0x20, 0x1, 0x21,
	0x36, 0xc4, 0x85, 0xf8, 0x83, 0xda, 0xcf, 0xb3,
	0x63, 0xc8, 0xf6, 0x4d, 0x6a, 0x82, 0xe5, 0x65,
	0x3d, 0x7d, 0x36, 0x64, 0x2b, 0x3a, 0x10, 0x8b,
	0x51, 0x55, 0x5a, 0x8d, 0x33, 0x40, 0x7d, 0x5c,
	0x22, 0x69, 0xc9, 0x52, 0x21, 0x4f, 0xce, 0x43,
	0xea, 0x5f, 0x80, 0x43, 0x10, 0xbb, 0xe6, 0x3e,
	0xd, 0xee, 0xcb, 0xf1, 0xe9, 0xba, 0x69, 0x5d,
	0xac, 0x77, 0x53, 0xb1, 0x31, 0xbc, 0xbf, 0xf3,
	0x98}

func errorOption() Option {
	return func(_ interface{}) error {
		return ErrOption
	}
}

func errorCredFinder(_ string) (Credential, error) {
	return nil, NewError("Not found")
}

func foundCredFinder(id string) (Credential, error) {
	return &testCred{
		user:      mockUser,
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
			defer func() { rand.Reader = oldRandReader }()

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
		AuthData []byte
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
					AttestationObject: mockRawAttestationObject,
				},
			},
			AuthData: mockRawAuthData,
			Fmt:      AttestationFormatNone,
			AttStmt:  []byte{0xa0},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {

			authData, fmt, attStmt, err := decodeAttestationObject(test.Cred)
			if err != nil {
				if test.Err {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err {
				tt.Fatalf("Did not get expected error")
			}
			if !bytes.Equal(authData, test.AuthData) {
				tt.Fatalf("AuthData mismatch got %#v expected %#v", authData, test.AuthData)
			}
			if fmt != test.Fmt {
				tt.Fatalf("Fmt mismatch got %s expected %s", fmt, test.Fmt)
			}
			if !bytes.Equal(attStmt, test.AttStmt) {
				tt.Fatalf("AttStmt mismatch got %#v expected %#v", attStmt, test.AttStmt)
			}
		})
	}
}

func TestVerifyAttestationStatement(t *testing.T) {
	type verifyTest struct {
		Name       string
		Fmt        AttestationStatementFormat
		AttStmt    cbor.RawMessage
		AuthData   []byte
		ClientData [32]byte
		Err        error
	}

	tests := []verifyTest{
		{
			Name: "bad",
			Fmt:  "wrong",
			Err:  ErrVerifyAttestation,
		},
		{
			Name:     "good none",
			Fmt:      "none",
			AttStmt:  cbor.RawMessage{0xa0},
			AuthData: mockRawAuthData,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyAttestationStatement(test.Fmt, test.AttStmt, test.AuthData, test.ClientData)
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
		Err        error
	}

	tests := []registrationTest{
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
					AttestationObject: mockRawAttestationObject,
				},
			},
			Err: ErrVerifyRegistration,
		},
		{
			Name:       "good",
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
						ClientDataJSON: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"https://e3b0c442.io"}`),
					},
					AttestationObject: mockRawAttestationObject,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			id, key, err := FinishRegistration(test.RP, test.CredFinder, test.Opts, test.Cred)
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
				tt.Fatal("Did not receive expected error")
			}
			if id != test.Cred.ID {
				tt.Fatal("ID doesn't match credential ID")
			}
			attObj := AttestationObject{}
			err = cbor.Unmarshal(test.Cred.Response.AttestationObject, &attObj)
			if err != nil {
				tt.Fatal("Unable to parse passed attestation object")
			}
			authData := AuthenticatorData{}
			err = authData.Decode(bytes.NewBuffer(attObj.AuthData))
			if err != nil {
				tt.Fatalf("Unable to parse passed authenticator data: %v", err)
			}
			k := COSEKey{}
			err = cbor.Unmarshal(key, &k)
			if err != nil {
				tt.Fatalf("Unable to unmarshal returned key")
			}
			if !reflect.DeepEqual(k, authData.AttestedCredentialData.CredentialPublicKey) {
				tt.Fatalf("Keys do not match")
			}

		})
	}
}
