package warp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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
	return []PublicKeyCredentialParameters{
		{
			Type: PublicKey,
			Alg:  ES256,
		},
	}
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

//CreateExtensions returns a creation option that adds one or more extensions
//to the creation options object
func CreateExtensions(exts AuthenticationExtensionsClientInputs) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Extensions = exts
	}
}

//FinishRegistration completes the registration ceremony by validating the
//provided public key credential, and returns the credential elements that need
//to be stored.
func FinishRegistration(
	rp RelyingParty,
	opts *PublicKeyCredentialCreationOptions,
	cred *AttestationPublicKeyCredential,
	extValidators ...ExtensionValidator,
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
	log.Printf("%#v", cred)
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
	_ = sha256.Sum256(cred.Response.ClientDataJSON)

	//8. Perform CBOR decoding on the attestationObject field of the
	//AuthenticatorAttestationResponse structure to obtain the attestation
	//statement format fmt, the authenticator data authData, and the attestation
	//statement attStmt.
	authData, _, _, err := decodeAttestationObject(cred)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Decode attestation object failed",
			Err:    err,
		}
	}

	//9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
	//expected by the Relying Party.
	if err := verifyRPIDHash(rp, authData); err != nil {
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
		opts.AuthenticatorSelection.UserVerification == Required {
		if !authData.UV {
			return nil, &ErrValidateRegistration{Detail: "User Verification required but missing"}
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
		case Supported:
		case Present:
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

func decodeAttestationObject(cred *AttestationPublicKeyCredential) (*AuthenticatorData, string, []byte, error) {
	attestationObj := AttestationObject{}
	err := cbor.Unmarshal(cred.Response.AttestationObject, &attestationObj)
	if err != nil {
		return nil, "", nil, &ErrValidateRegistration{Err: err}
	}

	var authData AuthenticatorData
	err = authData.Decode(bytes.NewBuffer(attestationObj.AuthData))
	if err != nil {
		return nil, "", nil, &ErrValidateRegistration{Err: err}
	}

	return &authData, attestationObj.Fmt, []byte(attestationObj.AttStmt), nil
}

func verifyRPIDHash(rp RelyingParty, authData *AuthenticatorData) error {
	rpIDHash := sha256.Sum256([]byte(rp.RelyingPartyID()))
	if !bytes.Equal(rpIDHash[:], authData.RPIDHash[:]) {
		return &ErrValidateRegistration{Detail: fmt.Sprintf("RPID hash does not match authData (RPID: %s)", rp.RelyingPartyID())}
	}
	return nil
}
