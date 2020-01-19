package warp

import (
	"bytes"
	"encoding/asn1"
	"regexp"

	"github.com/fxamacker/cbor"
)

var iso3166CountryCode = regexp.MustCompile(`[a-zA-Z]{2,3}`)
var idFidoGenCeAaguid asn1.ObjectIdentifier = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4})

//AttestationObject contains both authenticator data and an attestation
//statement.
type AttestationObject struct {
	AuthData AuthenticatorData
	Fmt      AttestationStatementFormat
	AttStmt  cbor.RawMessage
}

type encodingAttObj struct {
	AuthData []byte                     `cbor:"authData"`
	Fmt      AttestationStatementFormat `cbor:"fmt"`
	AttStmt  cbor.RawMessage            `cbor:"attStmt"`
}

//MarshalBinary implements the BinaryMarshaler interface, and returns the raw
//CBOR encoding of AttestationObject
func (ao *AttestationObject) MarshalBinary() (data []byte, err error) {
	rawAuthData, _ := (&ao.AuthData).MarshalBinary() //cannot fail

	intermediate := encodingAttObj{
		AuthData: rawAuthData,
		Fmt:      ao.Fmt,
		AttStmt:  ao.AttStmt,
	}

	return cbor.Marshal(&intermediate, cbor.CTAP2EncOptions())
}

//UnmarshalBinary implements the BinaryUnmarshaler interface, and populates an
//AttestationObject with the provided raw CBOR
func (ao *AttestationObject) UnmarshalBinary(data []byte) error {
	intermediate := encodingAttObj{}
	if err := cbor.Unmarshal(data, &intermediate); err != nil {
		return ErrUnmarshalAttestationObject.Wrap(err)
	}

	if err := (&ao.AuthData).UnmarshalBinary(intermediate.AuthData); err != nil {
		return ErrUnmarshalAttestationObject.Wrap(err)
	}

	ao.Fmt = intermediate.Fmt
	ao.AttStmt = intermediate.AttStmt
	return nil
}

//AttestationStatementFormat is the identifier for an attestation statement
//format.
type AttestationStatementFormat string

//enum values for AttestationStatementFormat
const (
	AttestationFormatPacked           AttestationStatementFormat = "packed"
	AttestationFormatTPM              AttestationStatementFormat = "tpm"
	AttestationFormatAndroidKey       AttestationStatementFormat = "android-key"
	AttestationFormatAndroidSafetyNet AttestationStatementFormat = "android-safetynet"
	AttestationFormatFidoU2F          AttestationStatementFormat = "fido-u2f"
	AttestationFormatNone             AttestationStatementFormat = "none"
)

//Valid determines if the Attestation Format Identifier is a valid value
func (asf AttestationStatementFormat) Valid() error {
	switch asf {
	case AttestationFormatPacked:
	case AttestationFormatTPM:
	case AttestationFormatAndroidKey:
	case AttestationFormatAndroidSafetyNet:
	case AttestationFormatFidoU2F:
	case AttestationFormatNone:
	default:
		return NewError("Invalid attestation statement %s", asf)
	}
	return nil
}

//VerifyNoneAttestationStatement verifies that at attestation statement of type
//"none" is valid
func VerifyNoneAttestationStatement(attStmt []byte, _ []byte, _ [32]byte) error {
	if !bytes.Equal([]byte(attStmt), []byte{0xa0}) { //empty map
		return ErrVerifyAttestation.Wrap(NewError("Attestation format none with non-empty statement: %#v", attStmt))
	}
	return nil
}
