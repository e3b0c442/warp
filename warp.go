package warp

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

//User defines functions which return data required about the authenticating
//user in order to perform WebAuthn transactions.
type User interface {
	UserName() string
	UserIcon() string
	UserID() []byte
	UserDisplayName() string
}

//RelyingParty defines functions which return data required about the Relying
//Party in order to perform WebAuthn transactions.
type RelyingParty interface {
	RelyingPartyID() string
	RelyingPartyName() string
	RelyingPartyIcon() string
	RelyingPartyOrigin() string
	CredentialExists([]byte) bool
}

//WebAuthnCredential represents the elements of a credential that must be stored
type WebAuthnCredential struct {
	ID        []byte
	PublicKey COSEKey
	User      PublicKeyCredentialUserEntity
}
