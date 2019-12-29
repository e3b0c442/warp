package warp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

//PublicKeyCredentialRpEntity is used to supply additional relying party
//attributes when creating a new credential - WebAuthn Level 1 TR § 5.4.2
type PublicKeyCredentialRpEntity struct {
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
	ID   string `json:"id"`
}

//PublicKeyCredentialUserEntity is used to supply additional account attributes
//when creating a new credential - § 5.4.3
type PublicKeyCredentialUserEntity struct {
	Name        string `json:"name"`
	Icon        string `json:"icon,omitempty"`
	ID          []byte `json:"id"`
	DisplayName string `json:"displayName"`
}

//PublicKeyCredentialType defines the valid credential types
type PublicKeyCredentialType string

//enum values for PublicKeyCredentialType type
const (
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

//COSEAlgorithmIdentifier is a number identifying a cryptographic algorithm. The
//algorithm identifiers SHOULD be values registered in the IANA COSE Algorithms
//registry.
type COSEAlgorithmIdentifier int

//enum values for COSEAlgorithmIdentifier type
const (
	CoseAlgorithmIdentifierES256 COSEAlgorithmIdentifier = -7
)

//PublicKeyCredentialParameters is used to supply additional parameters when
//creating a new credential - § 5.3
type PublicKeyCredentialParameters struct {
	Type PublicKeyCredentialType `json:"type"`
	Alg  COSEAlgorithmIdentifier `json:"alg"`
}

//AuthenticatorTransport defines hints as to how clients might communicate with
//a particular authenticator in order to obtain an assertion for a specific
//credential - § 5.10.4
type AuthenticatorTransport string

//enum values for AuthenticatorTransport type
const (
	AuthenticatorTransportUSB      AuthenticatorTransport = "usb"
	AuthenticatorTransportNFC      AuthenticatorTransport = "nfc"
	AuthenticatorTransportBLE      AuthenticatorTransport = "ble"
	AuthenticatorTransportInternal AuthenticatorTransport = "internal"
)

//PublicKeyCredentialDescriptor contains the attributes that are specified by a
//caller when referring to a public key credential as an input parameter to the
//create() or get() methods - § 5.10.3
type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType  `json:"type"`
	ID         []byte                   `json:"id"`
	Transports []AuthenticatorTransport `json:"transports"`
}

//AuthenticatorAttachment describes authenticators' attachment modalities -
//§ 5.4.5
type AuthenticatorAttachment string

//enum values for AuthenticatorAttachment type
const (
	AuthenticatorAttachmentPlatform      AuthenticatorAttachment = "platform"
	AuthenticatorAttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

//UserVerificationRequirement describes relying party user verification
//requirements - §5.10.6
type UserVerificationRequirement string

//enum values for UserVerificationRequirement type
const (
	UserVerificationRequirementRequired    UserVerificationRequirement = "required"
	UserVerificationRequirementPreferred   UserVerificationRequirement = "preferred"
	UserVerificationRequirementDiscouraged UserVerificationRequirement = "discouraged"
)

//AuthenticatorSelectionCriteria may be used by Relying Parties to specify their
//requirements regarding authenticator attributes - § 5.4.4
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment"`
	RequireResidentKey      bool                        `json:"requireResidentKey"`
	UserVerification        UserVerificationRequirement `json:"userVerification"`
}

//AttestationConveyancePreference may be used by Relying Parties to specify
//their preference regarding attestation conveyance during credential
//generation - § 5.4.6
type AttestationConveyancePreference string

//enum values for AttestationConveyancePreference type
const (
	AttestationConveyancePreferenceNone     AttestationConveyancePreference = "none"
	AttestationConveyancePreferenceIndirect AttestationConveyancePreference = "indirect"
	AttestationConveyancePreferenceDirect   AttestationConveyancePreference = "direct"
)

//PublicKeyCredentialCreationOptions implements the options for credential
//creation - § 5.4
type PublicKeyCredentialCreationOptions struct {
	RP                     PublicKeyCredentialRpEntity          `json:"rp"`
	User                   PublicKeyCredentialUserEntity        `json:"user"`
	Challenge              []byte                               `json:"challenge"`
	PubKeyCredParams       []PublicKeyCredentialParameters      `json:"pubKeyCredParams"`
	Timeout                *uint                                `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor      `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelectionCriteria      `json:"authenticatorSelection,omitempty"`
	Attestation            *AttestationConveyancePreference     `json:"attestation,omitempty"`
	Extensions             AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

//ChallengeLength represents the size of the generated challenge. Must be
//greater than 16.
var ChallengeLength = 32

//SupportedPublicKeyCredentialParameters enumerates the credential types and
//algorithms currently supported by this library.
func SupportedPublicKeyCredentialParameters() []PublicKeyCredentialParameters {
	return []PublicKeyCredentialParameters{
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  CoseAlgorithmIdentifierES256,
		},
	}
}

//CreationOption is a function that can be passed as a parameter to the
//BeginRegister function which adjusts the final credential creation options
//object.
type CreationOption func(*PublicKeyCredentialCreationOptions)

//StartRegister starts the registration process by creating a credential
//creation options object to be sent to the client.
func StartRegister(
	rp RelyingParty,
	user User,
	opts ...CreationOption,
) (
	*PublicKeyCredentialCreationOptions,
	*SessionData,
	error,
) {
	rpEntity := PublicKeyCredentialRpEntity{
		Name: rp.RelyingPartyName(),
		Icon: rp.RelyingPartyIcon(),
		ID:   rp.RelyingPartyID(),
	}

	userEntity := PublicKeyCredentialUserEntity{
		Name:        user.UserName(),
		Icon:        user.UserIcon(),
		ID:          user.UserID(),
		DisplayName: user.UserDisplayName(),
	}

	challenge := make([]byte, ChallengeLength)
	n, err := rand.Read(challenge)
	if err != nil {
		return nil, nil, &ErrRandIO{Detail: err.Error()}
	}
	if n < ChallengeLength {
		return nil, nil, &ErrRandIO{
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

	sessionData := SessionData{
		Challenge: challenge,
		Origin:    rp.RelyingPartyOrigin(),
	}

	for _, opt := range opts {
		opt(&creationOptions)
	}

	return &creationOptions, &sessionData, nil
}

//Timeout returns a creation option that adds a custom timeout to the creation
//options object
func Timeout(timeout uint) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Timeout = &timeout
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
		co.Attestation = &pref
	}
}

//CreateExtensions returns a creation option that adds one or more extensions
//to the creation options object
func CreateExtensions(exts AuthenticationExtensionsClientInputs) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Extensions = exts
	}
}

//AuthenticatorAttestationResponse represents the authenticator's response to a
//client’s request for the creation of a new public key credential. §5.2.1
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AttestationObject []byte `json:"attestationObject"`
}

//TokenBindingStatus represents a token binding status value. §5.10.1
type TokenBindingStatus string

//enum values for the TokenBindingStatus type
const (
	TokenBindingStatusSupported = "supported"
	TokenBindingStatusPresent   = "present"
)

//TokenBinding contains information about the state of the Token Binding
//protocol used when communicating with the Relying Party. §5.10.1
type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id"`
}

//CollectedClientData represents the contextual bindings of both the WebAuthn
//Relying Party and the client. §5.10.1
type CollectedClientData struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

//FinishRegistration accepts the authenticator attestation response and
//extension client outputs and validates the
func FinishRegistration(
	sess *SessionData,
	response AuthenticatorAttestationResponse,
	exts AuthenticationExtensionsClientOutputs,
	extValidators ...ExtensionValidator,
) (
	*Credential,
	error,
) {
	//Steps defined in §7.1

	//1. Let JSONtext be the result of running UTF-8 decode on the value of
	//response.clientDataJSON.
	//TODO research if there are any instances where the byte stream is not
	//valid JSON per the JSON decoder

	//2. Let C, the client data claimed as collected during the credential
	//creation, be the result of running an implementation-specific JSON parser
	//on JSONtext.
	C := CollectedClientData{}
	err := json.Unmarshal(response.ClientDataJSON, &C)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Unmarshal client data",
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
	rawChallenge, err := base64.RawURLEncoding.DecodeString(C.Challenge)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Decode challenge",
			Err:    &ErrUnmarshalClientData{Detail: err.Error()},
		}
	}
	if !bytes.Equal(rawChallenge, sess.Challenge) {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Challenge mismatch: got [% X] expected [% X]", rawChallenge, sess.Challenge),
		}
	}

	//5. Verify that the value of C.origin matches the Relying Party's origin.
	if !strings.EqualFold(C.Origin, sess.Origin) {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Origin mismatch: got %s expected %s", C.Origin, sess.Origin),
		}
	}

	//6. Verify that the value of C.tokenBinding.status matches the state of
	//Token Binding for the TLS connection over which the assertion was
	//obtained. If Token Binding was used on that TLS connection, also verify
	//that C.tokenBinding.id matches the base64url encoding of the Token Binding
	//ID for the connection.
	if C.TokenBinding != nil {
		switch C.TokenBinding.Status {
		case TokenBindingStatusSupported:
		case TokenBindingStatusPresent:
			if C.TokenBinding.ID == "" {
				return nil, &ErrValidateRegistration{
					Detail: "Token binding status present without ID",
				}
				//TODO implement Token Binding validation when support exists in
				//Golang standard library
			}
		default:
			return nil, &ErrValidateRegistration{
				Detail: fmt.Sprintf("Invalid token binding status %s", C.TokenBinding.Status),
			}
		}
	}

	//7. Compute the hash of response.clientDataJSON using SHA-256.
	_ = sha256.Sum256(response.ClientDataJSON)

	//8. Perform CBOR decoding on the attestationObject field of the
	//AuthenticatorAttestationResponse structure to obtain the attestation
	//statement format fmt, the authenticator data authData, and the attestation
	//statement attStmt.

	//

	return nil, nil
}
