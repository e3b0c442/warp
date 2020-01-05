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
	AuthData []byte                     `cbor:"authData"`
	Fmt      AttestationStatementFormat `cbor:"fmt"`
	AttStmt  cbor.RawMessage            `cbor:"attStmt"`
}

//AttestationStatementFormat is the identifier for an attestation statement
//format.
type AttestationStatementFormat string

//enum values for AttestationStatementFormat
const (
	StatementPacked           AttestationStatementFormat = "packed"
	StatementTPM              AttestationStatementFormat = "tpm"
	StatementAndroidKey       AttestationStatementFormat = "android-key"
	StatementAndroidSafetyNet AttestationStatementFormat = "android-safetynet"
	StatementFidoU2F          AttestationStatementFormat = "fido-u2f"
	StatementNone             AttestationStatementFormat = "none"
)

//Valid determines if the Attestation Format Identifier is a valid value
func (asf AttestationStatementFormat) Valid() error {
	switch asf {
	case StatementPacked:
	case StatementTPM:
	case StatementAndroidKey:
	case StatementAndroidSafetyNet:
	case StatementFidoU2F:
	case StatementNone:
	default:
		return NewError("Invalid attestation statement %s", asf)
	}
	return nil
}

//COSEKey represents a key decoded from COSE format.
type COSEKey struct {
	Kty       int             `cbor:"1,keyasint,omitempty"`
	Kid       []byte          `cbor:"2,keyasint,omitempty"`
	Alg       int             `cbor:"3,keyasint,omitempty"`
	KeyOpts   int             `cbor:"4,keyasint,omitempty"`
	IV        []byte          `cbor:"5,keyasint,omitempty"`
	CrvOrNOrK cbor.RawMessage `cbor:"-1,keyasint,omitempty"` // K for symmetric keys, Crv for elliptic curve keys, N for RSA modulus
	XOrE      cbor.RawMessage `cbor:"-2,keyasint,omitempty"` // X for curve x-coordinate, E for RSA public exponent
	Y         cbor.RawMessage `cbor:"-3,keyasint,omitempty"` // Y for curve y-cooridate
	D         []byte          `cbor:"-4,keyasint,omitempty"`
}

//VerifyNoneAttestationStatement verifies that at attestation statement of type
//"none" is valid
func VerifyNoneAttestationStatement(attStmt cbor.RawMessage, _ []byte, _ [32]byte) error {
	if !bytes.Equal([]byte(attStmt), []byte{0xa0}) { //empty map
		return ErrVerifyAttestation.Wrap(NewError("Attestation format none with non-empty statement: %#v", attStmt))
	}
	return nil
}
