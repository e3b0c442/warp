package warp

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fxamacker/cbor"
)

//AuthenticatorData encodes contextual bindings made by the authenticator.
type AuthenticatorData struct {
	RPIDHash               [32]byte
	UP                     bool
	UV                     bool
	AT                     bool
	ED                     bool
	SignCount              uint32
	AttestedCredentialData AttestedCredentialData
	Extensions             map[string]interface{}
}

//Decode decodes the ad hoc AuthenticatorData structure
func (ad *AuthenticatorData) Decode(data io.Reader) error {
	n, err := data.Read(ad.RPIDHash[:])
	if err != nil {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Read hash data failed: %v", err)}
	}
	if n < 32 {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Expected 32 bytes of hash data, got %d", n)}
	}

	var flags uint8
	err = binary.Read(data, binary.BigEndian, &flags)
	if err != nil {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Unable to read flag byte: %v", err)}
	}

	ad.UP = false
	ad.UV = false
	ad.AT = false
	ad.ED = false
	if flags&0x1 > 0 {
		ad.UP = true
	}
	if flags&0x4 > 0 {
		ad.UV = true
	}
	if flags&0x40 > 0 {
		ad.AT = true
	}
	if flags&0x80 > 0 {
		ad.ED = true
	}

	err = binary.Read(data, binary.BigEndian, &ad.SignCount)
	if err != nil {
		return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Unable to read sign count: %v", err)}
	}

	if ad.AT {
		err = ad.AttestedCredentialData.Decode(data)
		if err != nil {
			return &ErrBadAuthenticatorData{Err: err}
		}
	}

	if ad.ED {
		err = cbor.NewDecoder(data).Decode(&ad.Extensions)
		if err != nil {
			return &ErrBadAuthenticatorData{Detail: fmt.Sprintf("Unable to decode extensions: %v", err)}
		}
	}

	return nil
}
