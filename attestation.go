package warp

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fxamacker/cbor"
)

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
func (asf AttestationStatementFormat) Valid() bool {
	switch asf {
	case StatementPacked:
	case StatementTPM:
	case StatementAndroidKey:
	case StatementAndroidSafetyNet:
	case StatementFidoU2F:
	case StatementNone:
	default:
		return false
	}
	return true
}

//AttestedCredentialData is a variable-length byte array added to the
//authenticator data when generating an attestation object for a given
//credential. §6.4.1
type AttestedCredentialData struct {
	AAGUID              [16]byte
	CredentialID        []byte
	CredentialPublicKey crypto.PublicKey
}

//Decode decodes the attested credential data from a stream
func (acd *AttestedCredentialData) Decode(data io.Reader) error {
	n, err := data.Read(acd.AAGUID[:])
	if err != nil {
		return &ErrBadAttestedCredentialData{Detail: fmt.Sprintf("Read AAGUID failed: %v", err)}
	}
	if n < 16 {
		return &ErrBadAttestedCredentialData{Detail: fmt.Sprintf("Expected 16 bytes of AAGUID data, got %d", n)}
	}

	var credLen uint16
	err = binary.Read(data, binary.BigEndian, &credLen)
	if err != nil {
		return &ErrBadAttestedCredentialData{Detail: fmt.Sprintf("Unable to read credential length: %v", err)}
	}

	acd.CredentialID = make([]byte, credLen)
	n, err = data.Read(acd.CredentialID)
	if err != nil {
		return &ErrBadAttestedCredentialData{Detail: fmt.Sprintf("Read credential ID failed: %v", err)}
	}
	if uint16(n) < credLen {
		return &ErrBadAttestedCredentialData{Detail: fmt.Sprintf("Expected %d bytes of credential ID data, got %d", credLen, n)}
	}

	var credPK COSEKey
	err = cbor.NewDecoder(data).Decode(&credPK)
	if err != nil {
		return &ErrBadAttestedCredentialData{Detail: fmt.Sprintf("Unable to unmarshal COSE key: %v", err)}
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
	if len(attStmt) > 0 {
		return &ErrAttestationVerification{Detail: "Attestation format none with non-empty statement"}
	}
	return nil
}

//PackedAttestationStatement represents a decoded attestation statement of
//"packed" format
type PackedAttestationStatement struct {
	Alg        COSEAlgorithmIdentifier `cbor:"alg"`
	Sig        []byte                  `cbor:"sig"`
	X5C        [][]byte                `cbor:"x5c"`
	ECDAAKeyID []byte                  `cbor:"ecdaaKeyId"`
}

//VerifyPackedAttestationStatement verifies that an attestation statement of
//type "packed" is valid
func VerifyPackedAttestationStatement(rawAttStmt cbor.RawMessage, authData []byte, clientData [32]byte) error {
	//1. Verify that attStmt is valid CBOR conforming to the syntax defined
	//above and perform CBOR decoding on it to extract the contained fields.
	var attStmt PackedAttestationStatement
	err := cbor.Unmarshal(rawAttStmt, &attStmt)
	if err != nil {
		return &ErrAttestationVerification{
			Detail: fmt.Sprintf("Unable to decode packed attestation statement: %v", err),
		}
	}

	//2. If x5c is present, this indicates that the attestation type is not
	//ECDAA. In this case:
	if len(attStmt.X5C) > 0 {
		//Verify that sig is a valid signature over the concatenation of
		//authenticatorData and clientDataHash using the attestation public key
		//in attestnCert with the algorithm specified in alg.

		switch attStmt.Alg {
		case AlgorithmES256:
			pubKey, err := x509.ParsePKIXPublicKey(attStmt.X5C[0])
			if err != nil {
				return &ErrAttestationVerification{
					Detail: fmt.Sprintf("Unable to parse attestation public key: %v", err),
				}
			}

		}
	}

	return nil
}
