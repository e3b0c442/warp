package warp

//Error represents an error in a WebAuthn relying party operation
type Error struct {
	Msg     string
	Wrapped error
}

//Error implements the error interface
func (e Error) Error() string {
	return e.Msg
}

//Unwrap allows for error unwrapping
func (e Error) Unwrap() error {
	return e.Wrapped
}

//Wrap returns a new error which contains the provided error wrapped with this
//error
func (e Error) Wrap(err error) Error {
	n := e
	n.Wrapped = err
	return n
}

var (
	ErrDecodeAttestedCredentialData = Error{Msg: "Error decoding attested credential data"}
	ErrGenerateChallenge            = Error{Msg: "Error generating challenge"}
	ErrUnmarshalClientData          = Error{Msg: "Error unmarshaling client data"}
	ErrVerifyAttestation            = Error{Msg: "Error verifying attestation"}
	ErrVerifyRegistration           = Error{Msg: "Error verifying registration"}
)
