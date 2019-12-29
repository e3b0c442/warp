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
