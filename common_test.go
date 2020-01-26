package warp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"testing"
)

type badReader struct{}

func (*badReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrNoProgress
}

func TestGenerateChallenge(t *testing.T) {
	type challengeTest struct {
		Name        string
		AltReader   io.Reader
		AltLen      int
		ExpectedLen int
		Err         error
	}

	tests := []challengeTest{
		{
			Name:        "Good",
			ExpectedLen: ChallengeLength,
		},
		{
			Name:      "Bad reader",
			AltReader: &badReader{},
			Err:       io.ErrNoProgress,
		},
		{
			Name:      "Not enough bytes",
			AltReader: bytes.NewBuffer([]byte{1, 2, 3, 4, 5}),
			AltLen:    10,
			Err:       NewError("Read %d random bytes, needed %d", 5, 10),
		},
		{
			Name:        "Plenty of bytes",
			AltReader:   bytes.NewBuffer([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
			ExpectedLen: 5,
			AltLen:      5,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			if test.AltReader != nil {
				randReader = test.AltReader
				defer func() { randReader = rand.Reader }()
			}

			if test.AltLen != 0 {
				oldLen := ChallengeLength
				ChallengeLength = test.AltLen
				defer func() { ChallengeLength = oldLen }()
			}

			chal, err := generateChallenge()
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}

			if len(chal) != test.ExpectedLen {
				tt.Fatalf("Expected %d bytes, got %d", test.ExpectedLen, len(chal))
			}
		})
	}
}

func TestDecodeAuthData(t *testing.T) {
	type decodeTest struct {
		Name     string
		Raw      []byte
		Expected *AuthenticatorData
		Err      error
	}

	tests := []decodeTest{
		{
			Name: "Empty",
			Raw:  []byte{},
			Err:  ErrDecodeAuthenticatorData,
		},
		{
			Name: "Too short",
			Raw:  []byte{0x0},
			Err:  ErrDecodeAuthenticatorData,
		},
		{
			Name: "Good",
			Raw: []byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			Expected: &AuthenticatorData{
				RPIDHash: [32]byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				UP:                     false,
				UV:                     false,
				AT:                     false,
				ED:                     false,
				SignCount:              0,
				AttestedCredentialData: AttestedCredentialData{},
				Extensions:             nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ad, err := decodeAuthData(test.Raw)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if !reflect.DeepEqual(*ad, *test.Expected) {
				tt.Fatalf("Did not get expected result. Expected: %#v Actual %#v", *test.Expected, *ad)
			}
		})
	}
}

func TestParseClientData(t *testing.T) {
	type parseTest struct {
		Name     string
		JSONText []byte
		Expected *CollectedClientData
		Err      error
	}

	tests := []parseTest{
		{
			Name:     "Empty",
			JSONText: []byte{},
			Err:      NewError("Error unmarshaling client data JSON"),
		},
		{
			Name:     "Bad JSON",
			JSONText: []byte("<"),
			Err:      NewError("Error unmarshaling client data JSON"),
		},
		{
			Name:     "Good",
			JSONText: []byte(`{"type":"webauthn.create","challenge":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","origin":"e3b0c442.io"}`),
			Expected: &CollectedClientData{
				Type:      "webauthn.create",
				Challenge: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
				Origin:    "e3b0c442.io",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ccd, err := parseClientData(test.JSONText)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if !reflect.DeepEqual(*ccd, *test.Expected) {
				tt.Fatalf("Did not get expected output. Expected: %#v Actual: %#v", *test.Expected, *ccd)
			}
		})
	}
}

func TestVerifyChallenge(t *testing.T) {
	type verifyTest struct {
		Name      string
		CCD       *CollectedClientData
		Challenge []byte
		Err       bool
	}

	tests := []verifyTest{
		{
			Name: "Bad base64",
			CCD: &CollectedClientData{
				Challenge: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
			},
			Challenge: []byte{},
			Err:       true,
		},
		{
			Name: "No match",
			CCD: &CollectedClientData{
				Challenge: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
			},
			Challenge: []byte{
				0x00,
			},
			Err: true,
		},
		{
			Name: "Match",
			CCD: &CollectedClientData{
				Challenge: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
			},
			Challenge: []byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyChallenge(test.CCD, test.Challenge)
			if err != nil {
				if test.Err {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err {
				tt.Fatalf("Did not get expected error")
			}
		})
	}
}

type rpTest struct {
	id     string
	name   string
	icon   string
	origin string
}

func (rp *rpTest) EntityID() string {
	return rp.id
}

func (rp *rpTest) EntityName() string {
	return rp.name
}

func (rp *rpTest) EntityIcon() string {
	return rp.icon
}

func (rp *rpTest) Origin() string {
	return rp.origin
}

func TestVerifyOrigin(t *testing.T) {
	type verifyTest struct {
		Name string
		CCD  *CollectedClientData
		RP   RelyingParty
		Err  bool
	}

	tests := []verifyTest{
		{
			Name: "No match",
			CCD: &CollectedClientData{
				Origin: "good.com",
			},
			RP: &rpTest{
				origin: "bad.com",
			},
			Err: true,
		},
		{
			Name: "Match",
			CCD: &CollectedClientData{
				Origin: "e3b0c442.io",
			},
			RP: &rpTest{
				origin: "e3b0c442.io",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyOrigin(test.CCD, test.RP)
			if err != nil {
				if test.Err {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err {
				tt.Fatalf("Did not get expected error")
			}
		})
	}
}

func TestVerifyTokenBinding(t *testing.T) {
	type verifyTest struct {
		Name string
		CCD  *CollectedClientData
		Err  error
	}

	tests := []verifyTest{
		{
			Name: "Status without ID",
			CCD: &CollectedClientData{
				TokenBinding: &TokenBinding{
					Status: StatusPresent,
				},
			},
			Err: NewError("Token binding status present without ID"),
		},
		{
			Name: "Bad status",
			CCD: &CollectedClientData{
				TokenBinding: &TokenBinding{
					Status: "invalid",
				},
			},
			Err: NewError("Invalid token binding status invalid"),
		},
		{
			Name: "Good supported",
			CCD: &CollectedClientData{
				TokenBinding: &TokenBinding{
					Status: StatusSupported,
				},
			},
		},
		{
			Name: "Good present",
			CCD: &CollectedClientData{
				TokenBinding: &TokenBinding{
					Status: StatusPresent,
					ID:     "something",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyTokenBinding(test.CCD)
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

func TestVerifyRPIDHash(t *testing.T) {
	type verifyTest struct {
		Name     string
		RPID     string
		AuthData *AuthenticatorData
		Err      error
	}

	tests := []verifyTest{
		{
			Name: "Bad",
			RPID: "e3b0c442.io",
			AuthData: &AuthenticatorData{
				RPIDHash: sha256.Sum256([]byte("bad.com")),
			},
			Err: NewError("RPID hash does not match authData (RPID: e3b0c442.io)"),
		},
		{
			Name: "Good",
			RPID: "e3b0c442.io",
			AuthData: &AuthenticatorData{
				RPIDHash: sha256.Sum256([]byte("e3b0c442.io")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyRPIDHash(test.RPID, test.AuthData)
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

func TestVerifyUserPresent(t *testing.T) {
	type verifyTest struct {
		Name     string
		AuthData *AuthenticatorData
		Err      error
	}

	tests := []verifyTest{
		{
			Name: "good",
			AuthData: &AuthenticatorData{
				UP: true,
			},
		},
		{
			Name: "bad",
			AuthData: &AuthenticatorData{
				UP: false,
			},
			Err: NewError("User Present bit not set"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyUserPresent(test.AuthData)
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

func TestVerifyUserVerified(t *testing.T) {
	type verifyTest struct {
		Name     string
		AuthData *AuthenticatorData
		Err      error
	}

	tests := []verifyTest{
		{
			Name: "good",
			AuthData: &AuthenticatorData{
				UV: true,
			},
		},
		{
			Name: "bad",
			AuthData: &AuthenticatorData{
				UV: false,
			},
			Err: NewError("User Verification required but missing"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyUserVerified(test.AuthData)
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

func TestVerifyClientExtensionsOutputs(t *testing.T) {
	type verifyTest struct {
		Name string
		Ins  AuthenticationExtensionsClientInputs
		Outs AuthenticationExtensionsClientOutputs
		Err  error
	}

	tests := []verifyTest{
		{
			Name: "appid good",
			Ins: AuthenticationExtensionsClientInputs{
				"appid": "https://e3b0c442.io",
			},
			Outs: AuthenticationExtensionsClientOutputs{
				"appid": true,
			},
		},
		{
			Name: "appid missing",
			Ins:  AuthenticationExtensionsClientInputs{},
			Outs: AuthenticationExtensionsClientOutputs{
				"appid": true,
			},
			Err: NewError("Extension key appid provided in credential but not options"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := verifyClientExtensionsOutputs(test.Ins, test.Outs)
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
