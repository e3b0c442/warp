package warp

//User defines functions which return data required about the authenticating
//user in order to perform WebAuthn transactions.
type User interface {
	Name() string
	Icon() string
	ID() []byte
	DisplayName() string
	Credentials() []WebAuthnCredential
}

//UserFinder defines a function which returns an object takes a user handle as
//a parameter and returns an object which implements the User interface and an
//error
type UserFinder func([]byte) (User, error)

//RelyingParty defines functions which return data required about the Relying
//Party in order to perform WebAuthn transactions.
type RelyingParty interface {
	ID() string
	Name() string
	Icon() string
	Origin() string
	CredentialExists([]byte) bool
}

//WebAuthnCredential represents the elements of a credential that must be stored
type WebAuthnCredential struct {
	ID        []byte
	PublicKey COSEKey
	User      PublicKeyCredentialUserEntity
}

//ChallengeLength represents the size of the generated challenge. Must be
//greater than 16.
var ChallengeLength = 32

//SupportedAttestationStatementFormats returns the list of attestation formats
//currently supported by the library
func SupportedAttestationStatementFormats() []AttestationStatementFormat {
	return []AttestationStatementFormat{
		StatementNone,
	}
}

//SupportedKeyAlgorithms returns the list of key algorithms currently supported
//by the library
func SupportedKeyAlgorithms() []COSEAlgorithmIdentifier {
	return []COSEAlgorithmIdentifier{
		AlgorithmES256,
	}
}
