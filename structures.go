package warp

//CollectedClientData represents the contextual bindings of both the WebAuthn
//Relying Party and the client.
type CollectedClientData struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

//TokenBinding contains information about the state of the Token Binding
//protocol used when communicating with the Relying Party.
type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id,omitempty"`
}

//TokenBindingStatus represents a token binding status value.
type TokenBindingStatus string

//enum values for the TokenBindingStatus type
const (
	Supported = "supported"
	Present   = "present"
)

//PublicKeyCredentialType defines the valid credential types.
type PublicKeyCredentialType string

//enum values for PublicKeyCredentialType type
const (
	PublicKey PublicKeyCredentialType = "public-key"
)

//PublicKeyCredentialDescriptor contains the attributes that are specified by a
//caller when referring to a public key credential as an input parameter to the
//create() or get() methods.
type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType  `json:"type"`
	ID         []byte                   `json:"id"`
	Transports []AuthenticatorTransport `json:"transports,omitempty"`
}

//AuthenticatorTransport defines hints as to how clients might communicate with
//a particular authenticator in order to obtain an assertion for a specific
//credential.
type AuthenticatorTransport string

//enum values for AuthenticatorTransport type
const (
	USB      AuthenticatorTransport = "usb"
	NFC      AuthenticatorTransport = "nfc"
	BLE      AuthenticatorTransport = "ble"
	Internal AuthenticatorTransport = "internal"
)

//COSEAlgorithmIdentifier is a number identifying a cryptographic algorithm
type COSEAlgorithmIdentifier int

//enum values for COSEAlgorithmIdentifier type
const (
	ES256 COSEAlgorithmIdentifier = -7
)

//UserVerificationRequirement describes relying party user verification
//requirements
type UserVerificationRequirement string

//enum values for UserVerificationRequirement type
const (
	Required    UserVerificationRequirement = "required"
	Preferred   UserVerificationRequirement = "preferred"
	Discouraged UserVerificationRequirement = "discouraged"
)
