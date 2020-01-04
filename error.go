package warp

import "fmt"

//Error represents an error in a WebAuthn relying party operation
type Error struct {
	err     string
	wrapped error
}

//Error implements the error interface
func (e Error) Error() string {
	return e.err
}

//Unwrap allows for error unwrapping
func (e Error) Unwrap() error {
	return e.wrapped
}

//Wrap returns a new error which contains the provided error wrapped with this
//error
func (e Error) Wrap(err error) Error {
	n := e
	n.wrapped = err
	return n
}

//NewError returns a new Error with a custom message
func NewError(fmStr string, els ...interface{}) Error {
	return Error{
		err: fmt.Sprintf(fmStr, els...),
	}
}

var (
	ErrDecodeAttestedCredentialData = Error{err: "Error decoding attested credential data"}
	ErrDecodeAuthenticatorData      = Error{err: "Error decoding authenticator data"}
	ErrGenerateChallenge            = Error{err: "Error generating challenge"}
	ErrVerifyAttestation            = Error{err: "Error verifying attestation"}
	ErrVerifyClientExtensionOutput  = Error{err: "Error verifying client extension output"}
	ErrVerifyRegistration           = Error{err: "Error verifying registration"}
)
