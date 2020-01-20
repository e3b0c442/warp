package warp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/fxamacker/cbor"
)

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

//FIDOU2FAttestationStatement represents a decoded attestation statement of type
//"fido-u2f"
type FIDOU2FAttestationStatement struct {
	X5C [][]byte `cbor:"x5c"`
	Sig []byte   `cbor:"sig"`
}

//VerifyFIDOU2FAttestationStatement verifies that an attestation statement of
//type "fido-u2f" is valid
func VerifyFIDOU2FAttestationStatement(attStmt []byte, rawAuthData []byte, clientDataHash [32]byte) error {
	//1. Verify that attStmt is valid CBOR conforming to the syntax defined
	//above and perform CBOR decoding on it to extract the contained fields.
	var att FIDOU2FAttestationStatement
	if err := cbor.Unmarshal(attStmt, &att); err != nil {
		return ErrVerifyAttestation.Wrap(NewError("fido-u2f attestation statement not valid cbor").Wrap(err))
	}

	//2. Check that x5c has exactly one element and let attCert be that element.
	//Let certificate public key be the public key conveyed by attCert. If
	//certificate public key is not an Elliptic Curve (EC) public key over the
	//P-256 curve, terminate this algorithm and return an appropriate error.
	if len(att.X5C) != 1 {
		return ErrVerifyAttestation.Wrap(NewError("x5c does not have exactly one member"))
	}
	cert, err := x509.ParseCertificate(att.X5C[0])
	if err != nil {
		return ErrVerifyAttestation.Wrap(NewError("error parsing attestation certificate"))
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrVerifyAttestation.Wrap(NewError("certificate public key not ecdsa"))
	}
	if publicKey.Curve != elliptic.P256() {
		return ErrVerifyAttestation.Wrap(NewError("certificate public key not on P-256 curve"))
	}

	//3. Extract the claimed rpIdHash from authenticatorData, and the claimed
	//credentialId and credentialPublicKey from
	//authenticatorData.attestedCredentialData.
	var authData AuthenticatorData
	if err := (&authData).UnmarshalBinary(rawAuthData); err != nil {
		return ErrVerifyAttestation.Wrap(NewError("error parsing auth data").Wrap(err))
	}

	//4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of
	//[RFC8152]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW
	//in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
	var cosePublicKey COSEKey
	if err := cbor.Unmarshal(authData.AttestedCredentialData.CredentialPublicKey, &cosePublicKey); err != nil {
		return ErrVerifyAttestation.Wrap(NewError("error parsing credential public key").Wrap(err))
	}

	//Let x be the value corresponding to the "-2" key (representing x
	//coordinate) in credentialPublicKey, and confirm its size to be of 32
	//bytes. If size differs or "-2" key is not found, terminate this algorithm
	//and return an appropriate error.
	var x, y []byte
	if err := cbor.Unmarshal(cosePublicKey.XOrE, &x); err != nil {
		return ErrVerifyAttestation.Wrap(NewError("error parsing public key x parameter").Wrap(err))
	}
	if len(x) != 32 {
		return ErrVerifyAttestation.Wrap(NewError("unexpected length %d for public key x param", len(x)))
	}

	//Let y be the value corresponding to the "-3" key (representing y
	//coordinate) in credentialPublicKey, and confirm its size to be of 32
	//bytes. If size differs or "-3" key is not found, terminate this algorithm
	//and return an appropriate error.
	if err := cbor.Unmarshal(cosePublicKey.Y, &y); err != nil {
		return ErrVerifyAttestation.Wrap(NewError("error parsing public key y parameter").Wrap(err))
	}
	if len(y) != 32 {
		return ErrVerifyAttestation.Wrap(NewError("unexpected length %d for public key y param", len(y)))
	}

	//Let publicKeyU2F be the concatenation 0x04 || x || y.
	publicKeyU2F := append(append([]byte{0x04}, x...), y...)

	//Let verificationData be the concatenation of (0x00 || rpIdHash ||
	//clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of
	//[FIDO-U2F-Message-Formats]).
	verificationData := append(
		append(
			append(
				append(
					[]byte{0x00}, authData.RPIDHash[:]...,
				), clientDataHash[:]...,
			), authData.AttestedCredentialData.CredentialID...,
		), publicKeyU2F...,
	)

	if err = cert.CheckSignature(x509.ECDSAWithSHA256, verificationData, att.Sig); err != nil {
		return ErrVerifyAttestation.Wrap(NewError("error verifying certificate").Wrap(err))
	}

	return nil
}
