package warp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor"
)

//ChallengeLength represents the size of the generated challenge. Must be
//greater than 16.
var ChallengeLength = 32

//StartRegistration starts the registration ceremony by creating a credential
//creation options object to be sent to the client.
func StartRegistration(
	rp RelyingParty,
	user User,
	opts ...CreationOption,
) (
	*PublicKeyCredentialCreationOptions,
	error,
) {
	rpEntity := PublicKeyCredentialRPEntity{
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: rp.RelyingPartyName(),
			Icon: rp.RelyingPartyIcon(),
		},
		ID: rp.RelyingPartyID(),
	}

	userEntity := PublicKeyCredentialUserEntity{
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: user.UserName(),
			Icon: user.UserIcon(),
		},
		ID:          user.UserID(),
		DisplayName: user.UserDisplayName(),
	}

	challenge := make([]byte, ChallengeLength)
	n, err := rand.Read(challenge)
	if err != nil {
		return nil, &ErrRandIO{Detail: err.Error()}
	}
	if n < ChallengeLength {
		return nil, &ErrRandIO{
			Detail: fmt.Sprintf("Read %d random bytes, needed %d", n, ChallengeLength),
		}
	}

	credParams := SupportedPublicKeyCredentialParameters()

	creationOptions := PublicKeyCredentialCreationOptions{
		RP:               rpEntity,
		User:             userEntity,
		Challenge:        challenge,
		PubKeyCredParams: credParams,
	}

	for _, opt := range opts {
		opt(&creationOptions)
	}

	return &creationOptions, nil
}

//SupportedPublicKeyCredentialParameters enumerates the credential types and
//algorithms currently supported by this library.
func SupportedPublicKeyCredentialParameters() []PublicKeyCredentialParameters {
	supportedAlgs := SupportedKeyAlgorithms()
	params := make([]PublicKeyCredentialParameters, len(supportedAlgs))

	for i, alg := range supportedAlgs {
		params[i] = PublicKeyCredentialParameters{
			Type: PublicKey,
			Alg:  alg,
		}
	}

	return params
}

//CreationOption is a function that can be passed as a parameter to the
//BeginRegister function which adjusts the final credential creation options
//object.
type CreationOption func(*PublicKeyCredentialCreationOptions)

//Timeout returns a creation option that adds a custom timeout to the creation
//options object
func Timeout(timeout uint) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Timeout = timeout
	}
}

//ExcludeCredentials returns a creation option that adds a list of credentials
//to exclude to the creation options object
func ExcludeCredentials(creds []PublicKeyCredentialDescriptor) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.ExcludeCredentials = creds
	}
}

//AuthenticatorSelection returns a creation option that adds authenticator
//selection criteria to the creation options object
func AuthenticatorSelection(criteria AuthenticatorSelectionCriteria) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.AuthenticatorSelection = &criteria
	}
}

//Attestation returns a creation option that adds an attestation conveyance
//preference to the creation options object
func Attestation(pref AttestationConveyancePreference) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Attestation = pref
	}
}

//CreationExtensions returns a creation option that adds one or more extensions
//to the creation options object
func CreationExtensions(exts ...Extension) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Extensions = Extensions(exts...)
	}
}

//FinishRegistration completes the registration ceremony by validating the
//provided public key credential, and returns the credential elements that need
//to be stored.
func FinishRegistration(
	rp RelyingParty,
	opts *PublicKeyCredentialCreationOptions,
	cred *AttestationPublicKeyCredential,
) (
	*WebAuthnCredential,
	error,
) {
	//1. Let JSONtext be the result of running UTF-8 decode on the value of
	//response.clientDataJSON.
	//TODO research if there are any instances where the byte stream is not
	//valid JSON per the JSON decoder

	//2. Let C, the client data claimed as collected during the credential
	//creation, be the result of running an implementation-specific JSON parser
	//on JSONtext.
	C := CollectedClientData{}
	err := json.Unmarshal(cred.Response.ClientDataJSON, &C)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Unmarshal client data ",
			Err:    &ErrUnmarshalClientData{Detail: err.Error()},
		}
	}

	//3. Verify that the value of C.type is webauthn.create.
	if C.Type != "webauthn.create" {
		return nil, &ErrValidateRegistration{
			Detail: "C.type is not webauthn.create",
		}
	}

	//4. Verify that the value of C.challenge matches the challenge that was
	//sent to the authenticator in the create() call.
	if err = compareChallenge(&C, opts); err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Challenge comparison failed",
			Err:    err,
		}
	}

	//5. Verify that the value of C.origin matches the Relying Party's origin.
	if !strings.EqualFold(C.Origin, rp.RelyingPartyOrigin()) {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Origin mismatch: got %s expected %s", C.Origin, rp.RelyingPartyOrigin()),
		}
	}

	//6. Verify that the value of C.tokenBinding.status matches the state of
	//Token Binding for the TLS connection over which the assertion was
	//obtained. If Token Binding was used on that TLS connection, also verify
	//that C.tokenBinding.id matches the base64url encoding of the Token Binding
	//ID for the connection.
	if err = verifyTokenBinding(&C, opts); err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Token binding verification failed",
			Err:    err,
		}
	}

	//7. Compute the hash of response.clientDataJSON using SHA-256.
	clientDataHash := sha256.Sum256(cred.Response.ClientDataJSON)

	//8. Perform CBOR decoding on the attestationObject field of the
	//AuthenticatorAttestationResponse structure to obtain the attestation
	//statement format fmt, the authenticator data authData, and the attestation
	//statement attStmt.
	rawAuthData, attStmtFmt, attStmt, err := decodeAttestationObject(cred)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Decode attestation object failed",
			Err:    err,
		}
	}
	authData, err := decodeAuthData(rawAuthData)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Decode authenticator data failed",
			Err:    err,
		}
	}

	//9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
	//expected by the Relying Party.
	if err := verifyRPIDHash(opts.RP.ID, authData); err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Relying Party ID hash mismatch",
			Err:    err,
		}
	}

	//10. Verify that the User Present bit of the flags in authData is set.
	if !authData.UP {
		return nil, &ErrValidateRegistration{Detail: "User Presennt bit not set"}
	}

	//11. If user verification is required for this registration, verify that
	//the User Verified bit of the flags in authData is set.
	if opts.AuthenticatorSelection != nil &&
		opts.AuthenticatorSelection.UserVerification == VerificationRequired {
		if !authData.UV {
			return nil, &ErrValidateRegistration{Detail: "User Verification required but missing"}
		}
	}

	//12. Verify that the values of the client extension outputs in
	//clientExtensionResults and the authenticator extension outputs in the
	//extensions in authData are as expected, considering the client extension
	//input values that were given as the extensions option in the create()
	//call. In particular, any extension identifier values in the
	//clientExtensionResults and the extensions in authData MUST be also be
	//present as extension identifier values in the extensions member of
	//options, i.e., no extensions are present that were not requested. In the
	//general case, the meaning of "are as expected" is specific to the Relying
	//Party and which extensions are in use.
	if err := verifyClientExtensionsOutputs(opts, cred); err != nil {
		return nil, &ErrValidateRegistration{Detail: "Client extension outputs verification failed"}
	}

	//13. Determine the attestation statement format by performing a USASCII
	//case-sensitive match on fmt against the set of supported WebAuthn
	//Attestation Statement Format Identifier values. An up-to-date list of
	//registered WebAuthn Attestation Statement Format Identifier values is
	//maintained in the IANA registry of the same name [WebAuthn-Registries].
	if !attStmtFmt.Valid() {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Invalid attestation statement format %s", attStmtFmt),
		}
	}

	//14. Verify that attStmt is a correct attestation statement, conveying a
	//valid attestation signature, by using the attestation statement format
	//fmt’s verification procedure given attStmt, authData and the hash of the
	//serialized client data computed in step 7.
	if err := verifyAttestationStatement(attStmtFmt, attStmt, rawAuthData, clientDataHash); err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Attestation verification failed",
			Err:    err,
		}
	}
	return &WebAuthnCredential{}, nil
}

func compareChallenge(C *CollectedClientData, opts *PublicKeyCredentialCreationOptions) error {
	rawChallenge, err := base64.RawURLEncoding.DecodeString(C.Challenge)
	if err != nil {
		return err
	}

	if !bytes.Equal(rawChallenge, opts.Challenge) {
		return &ErrValidateRegistration{
			Detail: fmt.Sprintf("Challenge mismatch: got [% X] expected [% X]", rawChallenge, opts.Challenge),
		}
	}
	return nil
}

func verifyTokenBinding(C *CollectedClientData, opts *PublicKeyCredentialCreationOptions) error {
	if C.TokenBinding != nil {
		switch C.TokenBinding.Status {
		case StatusSupported:
		case StatusPresent:
			if C.TokenBinding.ID == "" {
				return &ErrValidateRegistration{
					Detail: "Token binding status present without ID",
				}
				//TODO implement Token Binding validation when support exists in
				//Golang standard library
			}
		default:
			return &ErrValidateRegistration{
				Detail: fmt.Sprintf("Invalid token binding status %s", C.TokenBinding.Status),
			}
		}
	}
	return nil
}

func decodeAttestationObject(cred *AttestationPublicKeyCredential) ([]byte, AttestationStatementFormat, cbor.RawMessage, error) {
	attestationObj := AttestationObject{}
	err := cbor.Unmarshal(cred.Response.AttestationObject, &attestationObj)
	if err != nil {
		return nil, "", nil, err
	}

	return attestationObj.AuthData, attestationObj.Fmt, attestationObj.AttStmt, nil
}

func decodeAuthData(raw []byte) (*AuthenticatorData, error) {
	var authData AuthenticatorData
	err := authData.Decode(bytes.NewBuffer(raw))
	if err != nil {
		return nil, err
	}
	return &authData, nil
}

func verifyRPIDHash(RPID string, authData *AuthenticatorData) error {
	rpIDHash := sha256.Sum256([]byte(RPID))
	if !bytes.Equal(rpIDHash[:], authData.RPIDHash[:]) {
		return &ErrValidateRegistration{
			Detail: fmt.Sprintf("RPID hash does not match authData (RPID: %s)", RPID),
		}
	}
	return nil
}

func verifyClientExtensionsOutputs(opts *PublicKeyCredentialCreationOptions, cred *AttestationPublicKeyCredential) error {
	for k, credV := range cred.Extensions {
		optsV, ok := opts.Extensions[k]
		if !ok {
			return &ErrValidateRegistration{
				Detail: fmt.Sprintf("Extension key %s provided in credential but not creation options", k),
			}
		}

		if validator, ok := ExtensionValidators[k]; ok { //ignore if no validator
			err := validator(optsV, credV)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyAttestationStatement(
	fmt AttestationStatementFormat,
	attStmt cbor.RawMessage,
	authData []byte,
	clientData [32]byte,
) error {
	switch fmt {
	case StatementNone:
		return VerifyNoneAttestationStatement(attStmt, authData, clientData)
	case StatementPacked:
		return VerifyPackedAttestationStatement(attStmt, authData, clientData)
	}

	return &ErrAttestationVerification{Detail: "Unsupported attestation format"}
}
