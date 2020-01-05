package warp

import (
	"encoding/binary"
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
		return ErrDecodeAuthenticatorData.Wrap(NewError("Error reanding relying party ID hash").Wrap(err))
	}
	if n < 32 {
		return ErrDecodeAuthenticatorData.Wrap(NewError("Expected 32 bytes of hash data, got %d", n))
	}

	var flags uint8
	err = binary.Read(data, binary.BigEndian, &flags)
	if err != nil {
		return ErrDecodeAuthenticatorData.Wrap(NewError("Error reading flag byte").Wrap(err))
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
		return ErrDecodeAuthenticatorData.Wrap(NewError("Error reading sign count").Wrap(err))
	}

	if ad.AT {
		err = ad.AttestedCredentialData.Decode(data)
		if err != nil {
			return ErrDecodeAuthenticatorData.Wrap(err)
		}
	}

	if ad.ED {
		err = cbor.NewDecoder(data).Decode(&ad.Extensions)
		if err != nil {
			return ErrDecodeAuthenticatorData.Wrap(err)
		}
	}

	return nil
}

//AttestedCredentialData is a variable-length byte array added to the
//authenticator data when generating an attestation object for a given
//credential. §6.4.1
type AttestedCredentialData struct {
	AAGUID              [16]byte
	CredentialID        []byte
	CredentialPublicKey COSEKey
}

//Decode decodes the attested credential data from a stream
func (acd *AttestedCredentialData) Decode(data io.Reader) error {
	n, err := data.Read(acd.AAGUID[:])
	if err != nil {
		return ErrDecodeAttestedCredentialData.Wrap(NewError("Error reading AAGUID").Wrap(err))
	}
	if n < 16 {
		return ErrDecodeAttestedCredentialData.Wrap(NewError("Expected 16 bytes of AAGUID data, got %d", n))
	}

	var credLen uint16
	err = binary.Read(data, binary.BigEndian, &credLen)
	if err != nil {
		return ErrDecodeAttestedCredentialData.Wrap(NewError("Error reading credential length").Wrap(err))
	}

	acd.CredentialID = make([]byte, credLen)
	n, err = data.Read(acd.CredentialID)
	if err != nil {
		return ErrDecodeAttestedCredentialData.Wrap(NewError("Error reading credential ID").Wrap(err))
	}
	if uint16(n) < credLen {
		return ErrDecodeAttestedCredentialData.Wrap(NewError("Expected %d bytes of credential ID data, got %d", credLen, n))
	}

	err = cbor.NewDecoder(data).Decode(&acd.CredentialPublicKey)
	if err != nil {
		return ErrDecodeAttestedCredentialData.Wrap(NewError("Error unmarshaling COSE key data").Wrap(err))
	}

	return nil
}
