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
	raw, err := (&mockAttestationObject).MarshalBinary()
	if err != nil {
		t.Fatalf("Got unexpected error %v", err)
	}
	if !bytes.Equal(raw, mockRawAttestationObject) {
		t.Fatalf("Output mismatch got %#v expected %#v", raw, []byte(mockRawAttestationObject))
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
			Raw:      mockRawAttestationObject,
			Expected: &mockAttestationObject,
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
