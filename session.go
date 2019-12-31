package warp

//SessionData contains the state required to manage registrations across
//multiple HTTP calls
type SessionData struct {
	Origin          string
	CreationOptions *PublicKeyCredentialCreationOptions
}
