package warp

import (
	"crypto/rand"
	"fmt"
)

//PublicKeyCredentialRpEntity is used to supply additional relying party
//attributes when creating a new credential - WebAuthn Level 1 TR § 5.4.2
type PublicKeyCredentialRpEntity struct {
	Name string `json:"name"`
	Icon string `json:"icon"`
	ID   string `json:"id"`
}

//PublicKeyCredentialUserEntity is used to supply additional account attributes
//when creating a new credential - § 5.4.3
type PublicKeyCredentialUserEntity struct {
	Name        string `json:"name"`
	Icon        string `json:"icon"`
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
	Timeout                uint                                 `json:"timeout"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor      `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelectionCriteria       `json:"authenticatorSelection"`
	Attestation            AttestationConveyancePreference      `json:"attestation"`
	Extensions             AuthenticationExtensionsClientInputs `json:"extensions"`
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

//BeginRegister begins the registration process by creating a credential
//creation options object to be sent to the client.
func BeginRegister(rp RelyingParty, user User, opts ...CreationOption) (*PublicKeyCredentialCreationOptions, error) {
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
		co.AuthenticatorSelection = criteria
	}
}

//Attestation returns a creation option that adds an attestation conveyance
//preference to the creation options object
func Attestation(pref AttestationConveyancePreference) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Attestation = pref
	}
}

//CreateExtensions returns a creatino option that adds one or more extensions
//to the creation options object
func CreateExtensions(exts AuthenticationExtensionsClientInputs) CreationOption {
	return func(co *PublicKeyCredentialCreationOptions) {
		co.Extensions = exts
	}
}
