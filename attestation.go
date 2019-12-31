package warp

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/fxamacker/cbor"
)

//AttestationObject contains both authenticator data and an attestation
//statement.
type AttestationObject struct {
	AuthData []byte          `cbor:"authData"`
	Fmt      string          `cbor:"fmt"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
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

	log.Printf("%#v", credPK)

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
