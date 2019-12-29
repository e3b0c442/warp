package warp

//RelyingParty defines functions which return data required about the Relying
//Party in order to perform WebAuthn transactions.
type RelyingParty interface {
	RelyingPartyID() string
	RelyingPartyName() string
	RelyingPartyIcon() string
}
