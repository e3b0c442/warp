package warp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/fxamacker/cbor"
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

	for _, opt := range opts {
		opt(&creationOptions)
	}

	sessionData := SessionData{
		Origin:          rp.RelyingPartyOrigin(),
		CreationOptions: &creationOptions,
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

//PublicKeyAttestationCredential represents a PublicKeyCredential with an
//attestation response
type PublicKeyAttestationCredential struct {
	ID         string                                `json:"id"`
	Type       string                                `json:"type"`
	RawID      string                                `json:"rawId"`
	Response   AuthenticatorAttestationResponse      `json:"response"`
	Extensions AuthenticationExtensionsClientOutputs `json:"extensions,omitempty"`
}

//AttestationObject contains both authenticator data and an attestation
//statement. §5.2.1
type AttestationObject struct {
	AuthData []byte          `cbor:"authData"`
	Fmt      string          `cbor:"fmt"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
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

//AuthenticatorData encodes contextual bindings made by the authenticator. §6.1
type AuthenticatorData struct {
	RPIDHash               [32]byte
	UP                     bool
	UV                     bool
	AT                     bool
	ED                     bool
	SignCount              uint32
	AttestedCredentialData AttestedCredentialData
	Extensions             map[string]interface{}
}

//Decode decodes the ad hoc AuthenticatorData structure
func (ad *AuthenticatorData) Decode(data io.Reader) error {
	n, err := data.Read(ad.RPIDHash[:])
	if err != nil {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Read hash data failed: %v", err)}
	}
	if n < 32 {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Expected 32 bytes of hash data, got %d", n)}
	}

	var flags uint8
	err = binary.Read(data, binary.BigEndian, &flags)
	if err != nil {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Unable to read flag byte: %v", err)}
	}

	ad.UP = false
	ad.UV = false
	ad.AT = false
	ad.ED = false
	if flags&0x1 > 0 {
		ad.UP = true
	}
	if flags&0x4 > 0 {
		ad.UV = true
	}
	if flags&0x40 > 0 {
		ad.AT = true
	}
	if flags&0x80 > 0 {
		ad.ED = true
	}

	err = binary.Read(data, binary.BigEndian, &ad.SignCount)
	if err != nil {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Unable to read sign count: %v", err)}
	}

	if ad.AT {
		err = ad.AttestedCredentialData.Decode(data)
		if err != nil {
			return &ErrBadAuthenticatorData{Err: err}
		}
	}

	if ad.ED {
		err = cbor.NewDecoder(data).Decode(&ad.Extensions)
		if err != nil {
			return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Unable to decode extensions: %v", err)}
		}
	}

	return nil
}

//FinishRegistration accepts the authenticator attestation response and
//extension client outputs and validates the
func FinishRegistration(
	sess *SessionData,
	cred PublicKeyAttestationCredential,
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
	err := json.Unmarshal(cred.Response.ClientDataJSON, &C)
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
	if !bytes.Equal(rawChallenge, sess.CreationOptions.Challenge) {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Challenge mismatch: got [% X] expected [% X]", rawChallenge, sess.CreationOptions.Challenge),
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
	_ = sha256.Sum256(cred.Response.ClientDataJSON)

	//8. Perform CBOR decoding on the attestationObject field of the
	//AuthenticatorAttestationResponse structure to obtain the attestation
	//statement format fmt, the authenticator data authData, and the attestation
	//statement attStmt.
	attestationObj := AttestationObject{}
	err = cbor.Unmarshal(cred.Response.AttestationObject, &attestationObj)
	if err != nil {
		return nil, &ErrValidateRegistration{Err: err}
	}
	var authData AuthenticatorData
	err = authData.Decode(bytes.NewBuffer(attestationObj.AuthData))
	if err != nil {
		return nil, &ErrValidateRegistration{Err: err}
	}
	log.Printf("%#v", authData)

	//9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
	//expected by the Relying Party.
	rpIDHash := sha256.Sum256([]byte(sess.CreationOptions.RP.ID))
	if !bytes.Equal(rpIDHash[:], authData.RPIDHash[:]) {
		return nil, &ErrValidateRegistration{Detail: fmt.Sprintf("RPID hash does not match authData (RPID: %s)", sess.CreationOptions.RP.ID)}
	}

	//10. Verify that the User Present bit of the flags in authData is set.
	if !authData.UP {
		return nil, &ErrValidateRegistration{Detail: "User Presennt bit not set"}
	}

	//11. If user verification is required for this registration, verify that
	//the User Verified bit of the flags in authData is set.
	if sess.CreationOptions.AuthenticatorSelection != nil &&
		sess.CreationOptions.AuthenticatorSelection.UserVerification == UserVerificationRequirementRequired {
		if !authData.UV {
			return nil, &ErrValidateRegistration{Detail: "User Verification required but missing"}
		}
	}

	return nil, nil
}
