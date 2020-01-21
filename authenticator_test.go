package warp

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestAuthenticatorDataDecode(t *testing.T) {
	type decodeTest struct {
		Name     string
		Reader   io.Reader
		Expected *AuthenticatorData
		Err      error
	}

	tests := []decodeTest{
		{
			Name:   "bad reader",
			Reader: &badReader{},
			Err:    ErrDecodeAuthenticatorData,
		},
		{
			Name:   "RPID too short",
			Reader: bytes.NewBuffer([]byte{0x00}),
			Err:    ErrDecodeAuthenticatorData,
		},
		{
			Name: "Unable to read flag byte",
			Reader: bytes.NewBuffer([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			}),
			Err: ErrDecodeAuthenticatorData,
		},
		{
			Name: "Unable to read sign count",
			Reader: bytes.NewBuffer([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0xC5,
				0x00, 0x00, 0x00,
			}),
			Err: ErrDecodeAuthenticatorData,
		},
		{
			Name: "Bad attested credential data",
			Reader: bytes.NewBuffer([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0x40,
				0x00, 0x00, 0x00, 0x00,
			}),
			Err: ErrDecodeAuthenticatorData,
		},
		{
			Name: "Bad extension data",
			Reader: bytes.NewBuffer([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0x80,
				0x00, 0x00, 0x00, 0x00,
			}),
			Err: ErrDecodeAuthenticatorData,
		},
		{
			Name: "Good no AT or ED",
			Reader: bytes.NewBuffer([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0x00,
				0x00, 0x00, 0x00, 0x00,
			}),
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
		{
			Name: "Good AT",
			Reader: bytes.NewBuffer(append([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0x40,
				0x00, 0x00, 0x00, 0x00,
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				0x00, 0x10,
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			}, goodP256Raw...)),
			Expected: &AuthenticatorData{
				RPIDHash: [32]byte{
					0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
					0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
					0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
					0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				},
				UP:        false,
				UV:        false,
				AT:        true,
				ED:        false,
				SignCount: 0,
				AttestedCredentialData: AttestedCredentialData{
					AAGUID: [16]byte{
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
						0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
					},
					CredentialID: []byte{
						0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
						0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
					},
					CredentialPublicKey: goodP256Raw,
				},
				Extensions: nil,
			},
		},
		{
			Name: "Bad extension after attested credential data",
			Reader: bytes.NewBuffer(append([]byte{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
				0xC0,
				0x00, 0x00, 0x00, 0x00,
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				0x00, 0x10,
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			}, goodP256Raw...)),
			Err: ErrDecodeAuthenticatorData,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ad := &AuthenticatorData{}
			err := ad.Decode(test.Reader)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			if !reflect.DeepEqual(*ad, *test.Expected) {
				tt.Fatalf("Did not get expected AuthenticatorData. Expected: %#v; actual: %#v", *test.Expected, *ad)
			}
		})
	}
}

func TestAttestedCredentialDataDecode(t *testing.T) {
	type decodeTest struct {
		Name     string
		Reader   io.Reader
		Expected *AttestedCredentialData
		Err      error
	}

	tests := []decodeTest{
		{
			Name:   "Bad reader",
			Reader: &badReader{},
			Err:    ErrDecodeAttestedCredentialData,
		},
		{
			Name: "AAGUID too short",
			Reader: bytes.NewBuffer([]byte{
				0x0,
			}),
			Err: ErrDecodeAttestedCredentialData,
		},
		{
			Name: "Unable to read credential ID length",
			Reader: bytes.NewBuffer([]byte{
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			}),
			Err: ErrDecodeAttestedCredentialData,
		},
		{
			Name: "Unable to read credential ID",
			Reader: bytes.NewBuffer([]byte{
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				0x00, 0x10,
			}),
			Err: ErrDecodeAttestedCredentialData,
		},
		{
			Name: "Unable to read credential public key",
			Reader: bytes.NewBuffer([]byte{
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				0x00, 0x10,
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			}),
			Err: ErrDecodeAttestedCredentialData,
		},
		{
			Name: "Good",
			Reader: bytes.NewBuffer(append([]byte{
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				0x00, 0x10,
				0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
			}, goodP256Raw...)),
			Expected: &AttestedCredentialData{
				AAGUID: [16]byte{
					0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
					0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				},
				CredentialID: []byte{
					0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
					0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
				},
				CredentialPublicKey: goodP256Raw,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ad := &AttestedCredentialData{}
			err := ad.Decode(test.Reader)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			if !reflect.DeepEqual(*ad, *test.Expected) {
				tt.Fatalf("Did not get expected AuthenticatorData. Expected: %#v; actual: %#v", *test.Expected, *ad)
			}
		})
	}
}

type limitedWriter struct {
	cap int
}

func (w *limitedWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.cap = w.cap - len(p)
	if w.cap < 0 {
		n = len(p) + w.cap
		w.cap = 0
	}
	return n, nil
}

type limitedErrWriter struct {
	cap int
}

func (w *limitedErrWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.cap = w.cap - len(p)
	if w.cap < 0 {
		n = len(p) + w.cap
		w.cap = 0
		return n, errors.New("error")
	}
	return n, nil
}

type badWriter struct{}

func (w *badWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("error")
}

func TestAttestedCredentialDataEncode(t *testing.T) {
	type encodeTest struct {
		Name     string
		ACD      *AttestedCredentialData
		Writer   io.Writer
		Expected []byte
		Err      error
	}

	tests := []encodeTest{
		{
			Name:   "bad writer",
			ACD:    &mockAttestedCredentialData,
			Writer: &badWriter{},
			Err:    ErrEncodeAttestedCredentialData,
		},
		{
			Name:   "AAGUID write too short",
			ACD:    &mockAttestedCredentialData,
			Writer: &limitedWriter{cap: 8},
			Err:    ErrEncodeAttestedCredentialData,
		},
		{
			Name:   "cred len write fail",
			ACD:    &mockAttestedCredentialData,
			Writer: &limitedErrWriter{cap: 16},
			Err:    ErrEncodeAttestedCredentialData,
		},
		{
			Name:   "cred id write fail",
			ACD:    &mockAttestedCredentialData,
			Writer: &limitedErrWriter{cap: 20},
			Err:    ErrEncodeAttestedCredentialData,
		},
		{
			Name:   "cred id write too short",
			ACD:    &mockAttestedCredentialData,
			Writer: &limitedWriter{cap: 20},
			Err:    ErrEncodeAttestedCredentialData,
		},
		{
			Name:   "cred pubkey write fail",
			ACD:    &mockAttestedCredentialData,
			Writer: &limitedWriter{cap: 64},
			Err:    ErrEncodeAttestedCredentialData,
		},
		{
			Name:     "good",
			ACD:      &mockAttestedCredentialData,
			Writer:   &bytes.Buffer{},
			Expected: mockRawAttestedCredentialData,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := test.ACD.Encode(test.Writer)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			b := test.Writer.(*bytes.Buffer)
			if !bytes.Equal(test.Expected, b.Bytes()) {
				tt.Fatalf("Output mismatch, expected %#v got %#v", test.Expected, b.Bytes())
			}
		})
	}

}

func TestAuthenticatorDataEncode(t *testing.T) {
	type encodeTest struct {
		Name     string
		AuthData *AuthenticatorData
		Writer   io.Writer
		Expected []byte
		Err      error
	}

	tests := []encodeTest{
		{
			Name:     "bad writer",
			AuthData: &mockAuthData,
			Writer:   &badWriter{},
			Err:      ErrEncodeAuthenticatorData,
		},
		{
			Name:     "RPIDHash write too short",
			AuthData: &mockAuthData,
			Writer:   &limitedWriter{cap: 16},
			Err:      ErrEncodeAuthenticatorData,
		},
		{
			Name: "flags write fail",
			AuthData: &AuthenticatorData{
				RPIDHash: [32]byte{
					0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
					0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
					0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
					0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				},
				UP:        true,
				UV:        true,
				AT:        true,
				ED:        true,
				SignCount: 1,
			},
			Writer: &limitedErrWriter{cap: 32},
			Err:    ErrEncodeAuthenticatorData,
		},
		{
			Name:     "sign count write fail",
			AuthData: &mockAuthData,
			Writer:   &limitedErrWriter{cap: 33},
			Err:      ErrEncodeAuthenticatorData,
		},
		{
			Name:     "attested credential write fail",
			AuthData: &mockAuthData,
			Writer:   &limitedWriter{cap: 37},
			Err:      ErrEncodeAuthenticatorData,
		},
		{
			Name: "extensions write fail",
			AuthData: &AuthenticatorData{
				RPIDHash: [32]byte{
					0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
					0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
					0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
					0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				},
				UP:         true,
				UV:         false,
				AT:         false,
				ED:         true,
				SignCount:  1,
				Extensions: map[string]interface{}{"appid": true},
			},
			Writer: &limitedWriter{cap: 37},
			Err:    ErrEncodeAuthenticatorData,
		},
		{
			Name:     "good",
			AuthData: &mockAuthData,
			Writer:   &bytes.Buffer{},
			Expected: mockRawAuthData,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := test.AuthData.Encode(test.Writer)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			b := test.Writer.(*bytes.Buffer)
			if !bytes.Equal(test.Expected, b.Bytes()) {
				tt.Fatalf("Output mismatch, expected %#v got %#v", test.Expected, b.Bytes())
			}
		})
	}
}

func TestAuthenticatorDataMarshalBinary(t *testing.T) {
	data, err := (&mockAuthData).MarshalBinary()
	if err != nil {
		t.Fatalf("Got unexpected error %v", err)
	}
	if !bytes.Equal(data, mockRawAuthData) {
		t.Fatalf("Output mismatch got %#v expected %#v", data, mockRawAuthData)
	}
}

func TestAuthenticatorDataUnmarshalBinary(t *testing.T) {
	ad := &AuthenticatorData{}
	err := ad.UnmarshalBinary(mockRawAuthData)

	if err != nil {
		t.Fatalf("Got unexpected error %v", err)
	}
	if !reflect.DeepEqual(*ad, mockAuthData) {
		t.Fatalf("Output mismatch got %#v expected %#v", ad, mockAuthData)
	}
}
