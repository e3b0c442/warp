package warp

//DetailedError defines a function to add details to returned errors for
//additional troubleshooting
type DetailedError interface {
	Details() string
}

//ErrRandIO represents an error reading from a cryptographically random source
type ErrRandIO struct {
	Detail string
}

func (e *ErrRandIO) Error() string {
	return "Random I/O read error"
}

//Details returns the error details
func (e *ErrRandIO) Details() string {
	return e.Detail
}

//ErrUnmarshalClientData represents an error unmarshaling a client data JSON
type ErrUnmarshalClientData struct {
	Detail string
}

func (e *ErrUnmarshalClientData) Error() string {
	return "Client data unmarshal error"
}

//Details returns the error details
func (e *ErrUnmarshalClientData) Details() string {
	return e.Detail
}

//ErrValidateRegistration represents an error validating a registration attempt.
//This error may wrap other errors.
type ErrValidateRegistration struct {
	Detail string
	Err    error
}

func (e *ErrValidateRegistration) Error() string {
	return "Registration validation error"
}

//Unwrap implements error wrapping
func (e *ErrValidateRegistration) Unwrap() error {
	return e.Err
}

//Details returns the error details
func (e *ErrValidateRegistration) Details() string {
	return e.Detail
}

//ErrBadAuthenticatorData represents an error decoding the authenticator data.
//This error may wrap other errors
type ErrBadAuthenticatorData struct {
	Detail string
	Err    error
}

func (e *ErrBadAuthenticatorData) Error() string {
	return "Bad authenticator data"
}

//Unwrap implements error wrapping
func (e *ErrBadAuthenticatorData) Unwrap() error {
	return e.Err
}

func (e *ErrBadAuthenticatorData) Details() string {
	return e.Detail
}

//ErrBadAttestedCredentialData represents an error decoding the attested
//credential data
type ErrBadAttestedCredentialData struct {
	Detail string
}

func (e *ErrBadAttestedCredentialData) Error() string {
	return "Bad attested credential data"
}

func (e *ErrBadAttestedCredentialData) Details() string {
	return e.Detail
}
