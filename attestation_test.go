package warp

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestAttestationStatementFormatValid(t *testing.T) {
	type validTest struct {
		Name string
		ASF  AttestationStatementFormat
		Err  bool
	}

	tests := []validTest{
		{
			Name: "Packed",
			ASF:  AttestationFormatPacked,
		},
		{
			Name: "TPM",
			ASF:  AttestationFormatTPM,
		},
		{
			Name: "Android Key",
			ASF:  AttestationFormatAndroidKey,
		},
		{
			Name: "Android SafetyNet",
			ASF:  AttestationFormatAndroidSafetyNet,
		},
		{
			Name: "FIDO U2F",
			ASF:  AttestationFormatFidoU2F,
		},
		{
			Name: "None",
			ASF:  AttestationFormatNone,
		},
		{
			Name: "Not in list",
			ASF:  AttestationStatementFormat("invalid"),
			Err:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			if err := test.ASF.Valid(); err != nil {
				if !test.Err {
					tt.Fatalf("Unexpected error for attestation statement format %s", test.ASF)
				}
				return
			}
			if test.Err {
				tt.Fatalf("Did not get expected error for attestation statement format %s", test.ASF)
			}
		})
	}
}

func TestVerifyNoneAttestationStatement(t *testing.T) {
	type noneTest struct {
		Name    string
		AttStmt []byte
		Err     error
	}

	tests := []noneTest{
		{
			Name:    "Good",
			AttStmt: []byte{0xa0},
		},
		{
			Name:    "Empty",
			AttStmt: []byte{},
			Err:     ErrVerifyAttestation,
		},
		{
			Name:    "No a0",
			AttStmt: []byte{0xde, 0xad, 0xbe, 0xef},
			Err:     ErrVerifyAttestation,
		},
		{
			Name:    "a0 with more",
			AttStmt: []byte{0xa0, 0xbe, 0xef},
			Err:     ErrVerifyAttestation,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := VerifyNoneAttestationStatement(test.AttStmt, nil, [32]byte{})
			if err != nil {
				if !errors.Is(err, test.Err) {
					tt.Fatalf("Got error \"%v\" instead of expected \"%v\"", err, test.Err)
				}
				return
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error for value [%0 x]", test.AttStmt)
			}
		})
	}

}

func TestAttestationObjectMarshalBinary(t *testing.T) {
	raw, err := (&mockNoneAttestationObject).MarshalBinary()
	if err != nil {
		t.Fatalf("Got unexpected error %v", err)
	}
	if !bytes.Equal(raw, mockRawNoneAttestationObject) {
		t.Fatalf("Output mismatch got %#v expected %#v", raw, []byte(mockRawNoneAttestationObject))
	}
}

func TestAttestationObjectUnmarshalBinary(t *testing.T) {
	type unmarshalTest struct {
		Name     string
		Raw      []byte
		Expected *AttestationObject
		Err      error
	}

	tests := []unmarshalTest{
		{
			Name: "bad attestation object",
			Raw:  []byte{},
			Err:  ErrUnmarshalAttestationObject,
		},
		{
			Name: "bad authData",
			Raw: []byte{
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
				0x48,                                           // byte string, 164 chars
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
			},
			Err: ErrUnmarshalAttestationObject,
		},
		{
			Name:     "good",
			Raw:      mockRawNoneAttestationObject,
			Expected: &mockNoneAttestationObject,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ao := &AttestationObject{}
			err := ao.UnmarshalBinary(test.Raw)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
			if !reflect.DeepEqual(*test.Expected, *ao) {
				tt.Fatalf("Output mismatch expected %#v got %#v", *test.Expected, *ao)
			}
		})
	}
}

func TestVerifyFIDOU2FAttestationStatement(t *testing.T) {
	type verifyTest struct {
		Name           string
		AttStmt        []byte
		RawAuthData    []byte
		ClientDataHash [32]byte
		Err            error
	}

	tests := []verifyTest{
		{
			Name:    "bad attestation statement CBOR",
			AttStmt: []byte{0x42},
			Err:     ErrVerifyAttestation,
		},
		{
			Name: "incorrect X5C len",
			AttStmt: []byte{
				0xa2,             // map 2 items
				0x63,             // text string 3 chars
				0x73, 0x69, 0x67, // "sig"
				0x41, // byte string, 1 byte
				0x01,
				0x63,             // text string 3 chars
				0x78, 0x35, 0x63, // "x5c"
				0x80, // array length 0
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name: "bad certificate",
			AttStmt: []byte{
				0xa2,             // map 2 items
				0x63,             // text string 3 chars
				0x73, 0x69, 0x67, // "sig"
				0x41, // byte string, 1 byte
				0x01,
				0x63,             // text string 3 chars
				0x78, 0x35, 0x63, // "x5c"
				0x81, // array, 1 member
				0x41, // byte string, 1 bytes
				0x01, 0x02, 0x03, 0x04,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name: "cert not ECDSA",
			AttStmt: []byte{
				0xa2,             // map 2 items
				0x63,             // text string 3 chars
				0x73, 0x69, 0x67, // "sig"
				0x41, // byte string, 1 byte
				0x01,
				0x63,             // text string 3 chars
				0x78, 0x35, 0x63, // "x5c"
				0x81,       // array, 1 member
				0x58, 0xb6, // byte string, 182 bytes
				0x30, 0x81, 0xb3, 0x30, 0x67, 0xa0, 0x3, 0x2, // Ed25519 cert
				0x1, 0x2, 0x2, 0x1, 0x0, 0x30, 0x5, 0x6, 0x3,
				0x2b, 0x65, 0x70, 0x30, 0x0, 0x30, 0x22, 0x18,
				0xf, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30,
				0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
				0x18, 0xf, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31,
				0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
				0x5a, 0x30, 0x0, 0x30, 0x2a, 0x30, 0x5, 0x6,
				0x3, 0x2b, 0x65, 0x70, 0x3, 0x21, 0x0, 0xbe,
				0x90, 0x7b, 0x4b, 0xac, 0x84, 0xfe, 0xe5, 0xce,
				0x88, 0x11, 0xdb, 0x2d, 0xef, 0xc9, 0xbf, 0xb,
				0x2a, 0x2a, 0x2b, 0xbc, 0x3d, 0x54, 0xd8, 0xa2,
				0x25, 0x7e, 0xcd, 0x70, 0x44, 0x19, 0x62, 0xa3,
				0x2, 0x30, 0x0, 0x30, 0x5, 0x6, 0x3, 0x2b,
				0x65, 0x70, 0x3, 0x41, 0x0, 0xe6, 0x13, 0x1,
				0x2d, 0x68, 0x90, 0x73, 0x4, 0xfc, 0x30, 0x2d,
				0x5d, 0x5a, 0x56, 0x49, 0x6, 0xb9, 0x77, 0x5a,
				0x7f, 0x34, 0x2b, 0x69, 0x8, 0x1e, 0x52, 0x97,
				0x3a, 0xb0, 0x83, 0xc3, 0xaf, 0x5, 0xd2, 0x49,
				0x7a, 0xf1, 0xe2, 0xd3, 0x58, 0xd5, 0xe8, 0x5a,
				0xeb, 0x8a, 0x7f, 0x6a, 0xbf, 0x82, 0xee, 0xb6,
				0x80, 0xfb, 0xd9, 0x55, 0xd7, 0x83, 0x30, 0x3,
				0x35, 0xad, 0x8b, 0x88, 0x7,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name: "cert not on P-256 curve",
			AttStmt: []byte{
				0xa2,             // map 2 items
				0x63,             // text string 3 chars
				0x73, 0x69, 0x67, // "sig"
				0x41, // byte string, 1 byte
				0x01,
				0x63,             // text string 3 chars
				0x78, 0x35, 0x63, // "x5c"
				0x81,       // array, 1 member
				0x58, 0xe3, // byte string, 227 bytes
				0x30, 0x81, 0xe0, 0x30, 0x81, 0x90, 0xa0, 0x3,
				0x2, 0x1, 0x2, 0x2, 0x1, 0x0, 0x30, 0xa,
				0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4,
				0x3, 0x2, 0x30, 0x0, 0x30, 0x22, 0x18, 0xf,
				0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31,
				0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18,
				0xf, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30,
				0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
				0x30, 0x0, 0x30, 0x4e, 0x30, 0x10, 0x6, 0x7,
				0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
				0x5, 0x2b, 0x81, 0x4, 0x0, 0x21, 0x3, 0x3a,
				0x0, 0x4, 0xbe, 0x90, 0x47, 0xd6, 0x58, 0x88,
				0xc8, 0x5e, 0x7b, 0x8a, 0xf4, 0xf4, 0x37, 0x70,
				0xb4, 0x94, 0xd6, 0x68, 0xf0, 0x58, 0x58, 0x83,
				0xc3, 0x54, 0x24, 0xf6, 0x25, 0xcb, 0x3a, 0x88,
				0x29, 0x4d, 0x35, 0x8b, 0x7b, 0xba, 0xb3, 0xea,
				0xab, 0x15, 0x1f, 0x2a, 0xd, 0x81, 0x6e, 0x28,
				0x2b, 0xdb, 0x1e, 0xb0, 0x35, 0x1d, 0xc6, 0x2d,
				0x11, 0xbb, 0xa3, 0x2, 0x30, 0x0, 0x30, 0xa,
				0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4,
				0x3, 0x2, 0x3, 0x3f, 0x0, 0x30, 0x3c, 0x2,
				0x1c, 0x36, 0x7b, 0x23, 0xe5, 0xe9, 0xd7, 0xfe,
				0xff, 0xa6, 0x92, 0xa2, 0x1a, 0x4f, 0x2f, 0x85,
				0xe5, 0xfa, 0x27, 0x65, 0xca, 0x71, 0x32, 0xe8,
				0x1c, 0x94, 0x71, 0x7e, 0xa3, 0x2, 0x1c, 0x8,
				0xeb, 0xab, 0x28, 0xbe, 0xf6, 0x46, 0x21, 0x67,
				0xff, 0xb9, 0xd6, 0x65, 0x6d, 0x7a, 0xe3, 0x9,
				0x61, 0x2b, 0xc5, 0xdc, 0xb6, 0x9e, 0xfe, 0x3e,
				0x19, 0xab, 0x67,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name:        "bad authData",
			AttStmt:     goodFIDOU2FAttStmt,
			RawAuthData: []byte{0x01},
			Err:         ErrVerifyAttestation,
		},
		{
			Name:    "bad credentialPublicKey",
			AttStmt: goodFIDOU2FAttStmt,
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, // authData.attestedCredentialData.credentialID
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, // |
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, // |
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, // v
				0x41,
				0x01,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name:    "bad credentialPublicKey x param",
			AttStmt: goodFIDOU2FAttStmt,
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
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
				0xa0,
				0x22, // key -3
				0x58, // byte string, >24 bytes
				0x20, // 32 bytes length
				0xb6, 0x72, 0x4, 0x62, 0x42, 0x44, 0x45, 0x2b,
				0x96, 0x4f, 0x5c, 0xab, 0x16, 0x1c, 0xd3, 0xc,
				0x76, 0x72, 0x6b, 0x9b, 0x36, 0x1d, 0xca, 0xdc,
				0xda, 0x2, 0xef, 0x1a, 0x5c, 0x71, 0xac, 0x78,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name:    "bad credentialPublicKey x param size",
			AttStmt: goodFIDOU2FAttStmt,
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
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
				0x1e, // 32 bytes length
				0x16, 0x16, 0xd7, 0xd0, 0x6a, 0x17, 0xd4, 0xff,
				0xbf, 0x16, 0x69, 0x3e, 0x6c, 0x60, 0x5, 0xe6,
				0xc7, 0x9, 0x16, 0x71, 0x6a, 0xf1, 0x3e, 0x95,
				0xc2, 0xf2, 0xda, 0xc8, 0x6, 0x7, 0x2e,
				0x22, // key -3
				0x58, // byte string, >24 bytes
				0x20, // 32 bytes length
				0xb6, 0x72, 0x4, 0x62, 0x42, 0x44, 0x45, 0x2b,
				0x96, 0x4f, 0x5c, 0xab, 0x16, 0x1c, 0xd3, 0xc,
				0x76, 0x72, 0x6b, 0x9b, 0x36, 0x1d, 0xca, 0xdc,
				0xda, 0x2, 0xef, 0x1a, 0x5c, 0x71, 0xac, 0x78,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name:    "bad credentialPublicKey y param",
			AttStmt: goodFIDOU2FAttStmt,
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
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
				0x16, 0x16, 0xd7, 0xd0, 0x6a, 0x17, 0xd4, 0xff,
				0xbf, 0x16, 0x69, 0x3e, 0x6c, 0x60, 0x5, 0xe6,
				0xc7, 0x9, 0x16, 0x71, 0x6a, 0xf1, 0x3e, 0x95,
				0xc2, 0xf2, 0xda, 0xc8, 0x6, 0x7, 0x2e, 0x8d,
				0x22, // key -3
				0xa0,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name:    "bad credentialPublicKey y param size",
			AttStmt: goodFIDOU2FAttStmt,
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
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
				0x16, 0x16, 0xd7, 0xd0, 0x6a, 0x17, 0xd4, 0xff,
				0xbf, 0x16, 0x69, 0x3e, 0x6c, 0x60, 0x5, 0xe6,
				0xc7, 0x9, 0x16, 0x71, 0x6a, 0xf1, 0x3e, 0x95,
				0xc2, 0xf2, 0xda, 0xc8, 0x6, 0x7, 0x2e, 0x8d,
				0x22, // key -3
				0x58, // byte string, >24 bytes
				0x1e, // 32 bytes length
				0xb6, 0x72, 0x4, 0x62, 0x42, 0x44, 0x45, 0x2b,
				0x96, 0x4f, 0x5c, 0xab, 0x16, 0x1c, 0xd3, 0xc,
				0x76, 0x72, 0x6b, 0x9b, 0x36, 0x1d, 0xca, 0xdc,
				0xda, 0x2, 0xef, 0x1a, 0x5c, 0x71, 0xac,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name: "bad sig",
			AttStmt: append([]byte{
				0xa2,             // map 2 items
				0x63,             // text string 3 chars
				0x73, 0x69, 0x67, // "sig"
				0x58, 0x48, // byte string, 72 bytes
				0x30, 0x46, 0x2, 0x21, 0x0, 0xe9, 0x43, 0x95,
				0xa1, 0x29, 0x61, 0x54, 0xbc, 0xe8, 0xa1, 0x71,
				0xcd, 0x2f, 0x8a, 0x74, 0xe4, 0xb5, 0x5f, 0x8c,
				0x60, 0x15, 0xfc, 0xc1, 0x21, 0x59, 0x51, 0xe4,
				0x4a, 0x90, 0x0, 0x93, 0x25, 0x2, 0x21, 0x0,
				0xf8, 0x22, 0x33, 0x7b, 0xc8, 0x8b, 0x14, 0xf1,
				0xf9, 0xca, 0x12, 0x9d, 0x82, 0x4e, 0xbf, 0xbb,
				0x22, 0x11, 0xe2, 0x5c, 0xa, 0x50, 0x5b, 0xac,
				0xfb, 0xab, 0xbb, 0xb8, 0x5, 0x5a, 0xd, 0x98,
				0x63,             // text string 3 chars
				0x78, 0x35, 0x63, // "x5c"
				0x81,       // array, 1 member
				0x58, 0xf6, // byte string, 246 bytes
			}, goodP256CertBytes...),
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
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
				0x16, 0x16, 0xd7, 0xd0, 0x6a, 0x17, 0xd4, 0xff,
				0xbf, 0x16, 0x69, 0x3e, 0x6c, 0x60, 0x5, 0xe6,
				0xc7, 0x9, 0x16, 0x71, 0x6a, 0xf1, 0x3e, 0x95,
				0xc2, 0xf2, 0xda, 0xc8, 0x6, 0x7, 0x2e, 0x8d,
				0x22, // key -3
				0x58, // byte string, >24 bytes
				0x20, // 32 bytes length
				0xb6, 0x72, 0x4, 0x62, 0x42, 0x44, 0x45, 0x2b,
				0x96, 0x4f, 0x5c, 0xab, 0x16, 0x1c, 0xd3, 0xc,
				0x76, 0x72, 0x6b, 0x9b, 0x36, 0x1d, 0xca, 0xdc,
				0xda, 0x2, 0xef, 0x1a, 0x5c, 0x71, 0xac, 0x78,
			},
			Err: ErrVerifyAttestation,
		},
		{
			Name:    "good",
			AttStmt: goodFIDOU2FAttStmt,
			RawAuthData: []byte{
				0xd8, 0x33, 0x51, 0x40, 0x80, 0xa0, 0xc7, 0x2b, //authdata.rpIDHash
				0x1e, 0xfa, 0x42, 0xb1, 0x8c, 0x96, 0xb9, 0x27, // |
				0x3e, 0x9f, 0x19, 0x3f, 0xa9, 0x80, 0xdb, 0x09, // |
				0xa0, 0x93, 0x33, 0x86, 0x5c, 0x2b, 0x32, 0xf3, // v
				0x41,               // authData.Flags
				0x0, 0x0, 0x0, 0x1, // authData.SignCount
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // authData.attestedCredentialData.aaguid
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // v
				0x0, 0x20, // authData.attestedCredentialData.credentialIDLength = 32
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
				0x16, 0x16, 0xd7, 0xd0, 0x6a, 0x17, 0xd4, 0xff,
				0xbf, 0x16, 0x69, 0x3e, 0x6c, 0x60, 0x5, 0xe6,
				0xc7, 0x9, 0x16, 0x71, 0x6a, 0xf1, 0x3e, 0x95,
				0xc2, 0xf2, 0xda, 0xc8, 0x6, 0x7, 0x2e, 0x8d,
				0x22, // key -3
				0x58, // byte string, >24 bytes
				0x20, // 32 bytes length
				0xb6, 0x72, 0x4, 0x62, 0x42, 0x44, 0x45, 0x2b,
				0x96, 0x4f, 0x5c, 0xab, 0x16, 0x1c, 0xd3, 0xc,
				0x76, 0x72, 0x6b, 0x9b, 0x36, 0x1d, 0xca, 0xdc,
				0xda, 0x2, 0xef, 0x1a, 0x5c, 0x71, 0xac, 0x78,
			},
			ClientDataHash: mockCreateClientDataJSONHash,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := VerifyFIDOU2FAttestationStatement(test.AttStmt, test.RawAuthData, test.ClientDataHash)
			if err != nil {
				err2 := err
				for err2 != nil {
					tt.Logf("%#v", err2)
					err2 = errors.Unwrap(err2)
				}
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
