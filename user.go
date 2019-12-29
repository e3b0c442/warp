package warp

//User defines functions which return data required about the authenticating
//user in order to perform WebAuthn transactions.
type User interface {
	UserName() string
	UserIcon() string
	UserID() []byte
	UserDisplayName() string
}
