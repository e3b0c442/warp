package warp

import (
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor"
)

//StartRegistration starts the registration ceremony by creating a credential
//creation options object to be sent to the client.
func StartRegistration(
	rp RelyingParty,
	user User,
	opts ...Option,
) (
	*PublicKeyCredentialCreationOptions,
	error,
) {
	rpEntity := PublicKeyCredentialRPEntity{
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: rp.Name(),
			Icon: rp.Icon(),
		},
		ID: rp.ID(),
	}

	userEntity := PublicKeyCredentialUserEntity{
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: user.Name(),
			Icon: user.Icon(),
		},
		ID:          user.ID(),
		DisplayName: user.DisplayName(),
	}

	challenge, err := generateChallenge()
	if err != nil {
		return nil, ErrGenerateChallenge.Wrap(err)
	}

	credParams := SupportedPublicKeyCredentialParameters()

	creationOptions := PublicKeyCredentialCreationOptions{
		RP:               rpEntity,
		User:             userEntity,
		Challenge:        challenge,
		PubKeyCredParams: credParams,
	}

	for _, opt := range opts {
		err = opt(&creationOptions)
		if err != nil {
			return nil, err
		}
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

//FinishRegistration completes the registration ceremony by validating the
//provided public key credential, and returns the credential elements that need
//to be stored.
func FinishRegistration(
	rp RelyingParty,
	opts *PublicKeyCredentialCreationOptions,
	cred *AttestationPublicKeyCredential,
) (
	string,
	[]byte,
	error,
) {
	//1. Let JSONtext be the result of running UTF-8 decode on the value of
	//response.clientDataJSON.
	//TODO research if there are any instances where the byte stream is not
	//valid JSON per the JSON decoder

	//2. Let C, the client data claimed as collected during the credential
	//creation, be the result of running an implementation-specific JSON parser
	//on JSONtext.
	C, err := parseClientData(cred.Response.ClientDataJSON)
	if err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//3. Verify that the value of C.type is webauthn.create.
	if C.Type != "webauthn.create" {
		return "", nil, ErrVerifyRegistration.Wrap(NewError("C.type is not webauthn.create"))
	}

	//4. Verify that the value of C.challenge matches the challenge that was
	//sent to the authenticator in the create() call.
	if err = verifyChallenge(C, opts.Challenge); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//5. Verify that the value of C.origin matches the Relying Party's origin.
	if err = verifyOrigin(C, rp); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//6. Verify that the value of C.tokenBinding.status matches the state of
	//Token Binding for the TLS connection over which the assertion was
	//obtained. If Token Binding was used on that TLS connection, also verify
	//that C.tokenBinding.id matches the base64url encoding of the Token Binding
	//ID for the connection.
	if err = verifyTokenBinding(C); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//7. Compute the hash of response.clientDataJSON using SHA-256.
	clientDataHash := sha256.Sum256(cred.Response.ClientDataJSON)

	//8. Perform CBOR decoding on the attestationObject field of the
	//AuthenticatorAttestationResponse structure to obtain the attestation
	//statement format fmt, the authenticator data authData, and the attestation
	//statement attStmt.
	rawAuthData, attStmtFmt, attStmt, err := decodeAttestationObject(cred)
	if err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}
	authData, err := decodeAuthData(rawAuthData)
	if err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
	//expected by the Relying Party.
	if err := verifyRPIDHash(opts.RP.ID, authData); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//10. Verify that the User Present bit of the flags in authData is set.
	if err := verifyUserPresent(authData); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//11. If user verification is required for this registration, verify that
	//the User Verified bit of the flags in authData is set.
	if opts.AuthenticatorSelection != nil &&
		opts.AuthenticatorSelection.UserVerification == VerificationRequired {
		if err = verifyUserVerified(authData); err != nil {
			return "", nil, ErrVerifyRegistration.Wrap(err)
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
	if err := verifyClientExtensionsOutputs(opts.Extensions, cred.Extensions); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//13. Determine the attestation statement format by performing a USASCII
	//case-sensitive match on fmt against the set of supported WebAuthn
	//Attestation Statement Format Identifier values. An up-to-date list of
	//registered WebAuthn Attestation Statement Format Identifier values is
	//maintained in the IANA registry of the same name [WebAuthn-Registries].
	if err := attStmtFmt.Valid(); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//14. Verify that attStmt is a correct attestation statement, conveying a
	//valid attestation signature, by using the attestation statement format
	//fmt’s verification procedure given attStmt, authData and the hash of the
	//serialized client data computed in step 7.
	if err := verifyAttestationStatement(attStmtFmt, attStmt, rawAuthData, clientDataHash); err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(err)
	}

	//15. If validation is successful, obtain a list of acceptable trust anchors
	//(attestation root certificates or ECDAA-Issuer public keys) for that
	//attestation type and attestation statement format fmt, from a trusted
	//source or from policy.
	//TODO once other attestation formats are implemented

	//16. Assess the attestation trustworthiness using the outputs of the
	//verification procedure
	//TODO once other attestation formats are implemented

	//17. Check that the credentialId is not yet registered to any other user.
	//If registration is requested for a credential that is already registered
	//to a different user, the Relying Party SHOULD fail this registration
	//ceremony, or it MAY decide to accept the registration, e.g. while deleting
	//the older registration.
	//TODO implement optional deletion
	if rp.CredentialExists(authData.AttestedCredentialData.CredentialID) {
		return "", nil, ErrVerifyRegistration.Wrap(NewError("Credential with this ID already exists"))
	}

	//18. If the attestation statement attStmt verified successfully and is
	//found to be trustworthy, then register the new credential with the account
	//that was denoted in the options.user passed to create(), by associating it
	//with the credentialId and credentialPublicKey in the
	//attestedCredentialData in authData, as appropriate for the Relying Party's
	//system.
	rawKey, err := cbor.Marshal(authData.AttestedCredentialData.CredentialPublicKey, cbor.EncOptions{
		Sort: cbor.SortCTAP2,
	})
	if err != nil {
		return "", nil, ErrVerifyRegistration.Wrap(NewError("Unable to marshal raw key"))
	}

	return cred.ID, rawKey, nil
}

func decodeAttestationObject(cred *AttestationPublicKeyCredential) ([]byte, AttestationStatementFormat, cbor.RawMessage, error) {
	attestationObj := AttestationObject{}
	err := cbor.Unmarshal(cred.Response.AttestationObject, &attestationObj)
	if err != nil {
		return nil, "", nil, err
	}

	return attestationObj.AuthData, attestationObj.Fmt, attestationObj.AttStmt, nil
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
	}

	return ErrVerifyAttestation.Wrap(errors.New("Unsupported attestation format"))
}
