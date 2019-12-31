package warp

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
}

//WebAuthnCredential represents the elements of a credential that must be stored
type WebAuthnCredential struct{}
