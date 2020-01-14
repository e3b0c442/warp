package warp

import (
	"errors"
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
