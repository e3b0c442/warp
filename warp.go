package warp

//User defines functions which return data required about the authenticating
//user in order to perform WebAuthn transactions.
type User interface {
	Name() string
	Icon() string
	ID() []byte
	DisplayName() string
	Credentials() map[string]Credential
}

//UserFinder defines a function which takes a user handle as a parameter and
//returns an object which implements the User interface and an error
type UserFinder func([]byte) (User, error)

//Credential defines functions which return data required about the stored
//credentials
type Credential interface {
	User() User
	ID() string
	PublicKey() []byte
	SignCount() uint
}

//CredentialFinder defines a function which takes a credential ID as a parameter
//and returns an object which implements the Credential interface and an error
type CredentialFinder func(string) (Credential, error)

//RelyingParty defines functions which return data required about the Relying
//Party in order to perform WebAuthn transactions.
type RelyingParty interface {
	ID() string
	Name() string
	Icon() string
	Origin() string
}

//ChallengeLength represents the size of the generated challenge. Must be
//greater than 16.
var ChallengeLength = 32

//SupportedAttestationStatementFormats returns the list of attestation formats
//currently supported by the library
func SupportedAttestationStatementFormats() []AttestationStatementFormat {
	return []AttestationStatementFormat{
		AttestationFormatNone,
	}
}

//SupportedKeyAlgorithms returns the list of key algorithms currently supported
//by the library
func SupportedKeyAlgorithms() []COSEAlgorithmIdentifier {
	return []COSEAlgorithmIdentifier{
		AlgorithmEdDSA,
		AlgorithmES512,
		AlgorithmES384,
		AlgorithmES256,
		AlgorithmPS512,
		AlgorithmPS384,
		AlgorithmPS256,
		AlgorithmRS512,
		AlgorithmRS384,
		AlgorithmRS256,
		AlgorithmRS1,
	}
}
