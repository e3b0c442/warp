package warp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"math/big"

	"github.com/fxamacker/cbor"
)

//COSEKey represents a key decoded from COSE format.
type COSEKey struct {
	Kty       int             `cbor:"1,keyasint,omitempty"`
	Kid       []byte          `cbor:"2,keyasint,omitempty"`
	Alg       int             `cbor:"3,keyasint,omitempty"`
	KeyOpts   int             `cbor:"4,keyasint,omitempty"`
	IV        []byte          `cbor:"5,keyasint,omitempty"`
	CrvOrNOrK cbor.RawMessage `cbor:"-1,keyasint,omitempty"` // K for symmetric keys, Crv for elliptic curve keys, N for RSA modulus
	XOrE      cbor.RawMessage `cbor:"-2,keyasint,omitempty"` // X for curve x-coordinate, E for RSA public exponent
	Y         cbor.RawMessage `cbor:"-3,keyasint,omitempty"` // Y for curve y-cooridate
	D         []byte          `cbor:"-4,keyasint,omitempty"`
}

//COSEAlgorithmIdentifier is a number identifying a cryptographic algorithm
type COSEAlgorithmIdentifier int

//enum values for COSEAlgorithmIdentifier type
const (
	AlgorithmRS1   COSEAlgorithmIdentifier = -65535
	AlgorithmRS512 COSEAlgorithmIdentifier = -259
	AlgorithmRS384 COSEAlgorithmIdentifier = -258
	AlgorithmRS256 COSEAlgorithmIdentifier = -257
	AlgorithmPS512 COSEAlgorithmIdentifier = -39
	AlgorithmPS384 COSEAlgorithmIdentifier = -38
	AlgorithmPS256 COSEAlgorithmIdentifier = -37
	AlgorithmES512 COSEAlgorithmIdentifier = -36
	AlgorithmES384 COSEAlgorithmIdentifier = -35
	AlgorithmEdDSA COSEAlgorithmIdentifier = -8
	AlgorithmES256 COSEAlgorithmIdentifier = -7
)

//COSEEllipticCurve is a number identifying an elliptic curve
type COSEEllipticCurve int

//enum values for COSEEllipticCurve type
const (
	CurveP256 COSEEllipticCurve = 1
	CurveP384 COSEEllipticCurve = 2
	CurveP521 COSEEllipticCurve = 3
)

//VerifySignature verifies a signature using a provided COSEKey, message, and
//signature
func VerifySignature(rawKey cbor.RawMessage, message, sig []byte) error {
	coseKey := COSEKey{}
	err := cbor.Unmarshal(rawKey, &coseKey)
	if err != nil {
		return ErrVerifySignature.Wrap(ErrDecodeCOSEKey.Wrap(err))
	}

	publicKey, err := DecodePublicKey(&coseKey)
	if err != nil {
		return ErrVerifySignature.Wrap(err)
	}

	switch COSEAlgorithmIdentifier(coseKey.Alg) {
	case AlgorithmES256,
		AlgorithmES384,
		AlgorithmES512:
		pk, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrVerifySignature.Wrap(NewError("Invalid public key type for ECDSA algorithm"))
		}

		type ECDSASignature struct {
			R, S *big.Int
		}

		ecdsaSig := ECDSASignature{}
		_, err := asn1.Unmarshal(sig, &ecdsaSig)
		if err != nil {
			return ErrVerifySignature.Wrap(NewError("Unable to parse ECDSA signature").Wrap(err))
		}

		var msgHash []byte
		switch COSEAlgorithmIdentifier(coseKey.Alg) {
		case AlgorithmES256:
			h := sha256.Sum256(message)
			msgHash = h[:]
		case AlgorithmES384:
			h := sha512.Sum384(message)
			msgHash = h[:]
		case AlgorithmES512:
			h := sha512.Sum512(message)
			msgHash = h[:]
		}
		if ecdsa.Verify(pk, msgHash, ecdsaSig.R, ecdsaSig.S) {
			return nil
		}
		return NewError("ECDSA signature verification failed")

	case AlgorithmRS1,
		AlgorithmRS512,
		AlgorithmRS384,
		AlgorithmRS256,
		AlgorithmPS512,
		AlgorithmPS384,
		AlgorithmPS256:
		pk, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return ErrVerifySignature.Wrap(NewError("Invalid public key type for RSA algorithm"))
		}

		var c crypto.Hash
		switch COSEAlgorithmIdentifier(coseKey.Alg) {
		case AlgorithmRS512, AlgorithmPS512:
			c = crypto.SHA512
		case AlgorithmRS384, AlgorithmPS384:
			c = crypto.SHA384
		case AlgorithmRS256, AlgorithmPS256:
			c = crypto.SHA256
		}

		h := c.New()
		h.Write(message)

		switch COSEAlgorithmIdentifier(coseKey.Alg) {
		case AlgorithmRS512, AlgorithmRS384, AlgorithmRS256, AlgorithmRS1:
			err = rsa.VerifyPKCS1v15(pk, c, h.Sum(nil), sig)
		case AlgorithmPS512, AlgorithmPS384, AlgorithmPS256:
			err = rsa.VerifyPSS(pk, c, h.Sum(nil), sig, nil)
		}

		if err != nil {
			return ErrVerifySignature.Wrap(NewError("RSA signature verification failed"))
		}

	case AlgorithmEdDSA:
		pk, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return ErrVerifySignature.Wrap(NewError("Invalid public key type for EdDSA algorithm"))
		}
		if ed25519.Verify(pk, message, sig) {
			return nil
		}
		return ErrVerifySignature.Wrap(NewError("EdDSA signature verification failed"))
	}
	return ErrVerifySignature.Wrap(NewError("COSE algorithm ID %d not supported", coseKey.Alg))
}

//DecodePublicKey parses a crypto.PublicKey from a COSEKey
func DecodePublicKey(coseKey *COSEKey) (crypto.PublicKey, error) {
	var publicKey crypto.PublicKey

	switch COSEAlgorithmIdentifier(coseKey.Alg) {
	case AlgorithmES256,
		AlgorithmES384,
		AlgorithmES512:
		k, err := decodeECDSAPublicKey(coseKey)
		if err != nil {
			return nil, ErrDecodeCOSEKey.Wrap(err)
		}
		publicKey = k
	case AlgorithmRS1,
		AlgorithmRS512,
		AlgorithmRS384,
		AlgorithmRS256,
		AlgorithmPS512,
		AlgorithmPS384,
		AlgorithmPS256:
		k, err := decodeRSAPublicKey(coseKey)
		if err != nil {
			return nil, ErrDecodeCOSEKey.Wrap(err)
		}
		publicKey = k
	case AlgorithmEdDSA:
		k, err := decodeEd25519PublicKey(coseKey)
		if err != nil {
			return nil, ErrDecodeCOSEKey.Wrap(err)
		}
		publicKey = k
	default:
		return nil, ErrDecodeCOSEKey.Wrap(NewError("COSE algorithm ID %d not supported", coseKey.Alg))
	}

	return publicKey, nil
}

func decodeECDSAPublicKey(coseKey *COSEKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	var curveID int
	if err := cbor.Unmarshal(coseKey.CrvOrNOrK, &curveID); err != nil {
		return nil, NewError("Error decoding elliptic curve ID").Wrap(err)
	}

	switch COSEEllipticCurve(curveID) {
	case CurveP256:
		curve = elliptic.P256()
	case CurveP384:
		curve = elliptic.P384()
	case CurveP521:
		curve = elliptic.P521()
	default:
		return nil, NewError("COSE elliptic curve %d not supported", curveID)
	}

	var xBytes, yBytes []byte
	if err := cbor.Unmarshal(coseKey.XOrE, &xBytes); err != nil {
		return nil, NewError("Error decoding elliptic X parameter").Wrap(err)
	}
	if err := cbor.Unmarshal(coseKey.Y, &yBytes); err != nil {
		return nil, NewError("Error decoding elliptic Y parameter").Wrap(err)
	}

	var x, y *big.Int
	x = x.SetBytes(xBytes)
	y = y.SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func decodeRSAPublicKey(coseKey *COSEKey) (*rsa.PublicKey, error) {
	var nBytes, eBytes []byte
	if err := cbor.Unmarshal(coseKey.CrvOrNOrK, &nBytes); err != nil {
		return nil, NewError("Error decoding RSA modulus").Wrap(err)
	}
	if err := cbor.Unmarshal(coseKey.XOrE, &eBytes); err != nil {
		return nil, NewError("Error decoding RSA exponent").Wrap(err)
	}

	var n *big.Int
	var e int
	n = n.SetBytes(nBytes)
	if err := binary.Read(bytes.NewBuffer(eBytes), binary.BigEndian, &e); err != nil {
		return nil, NewError("Error decoding RSA exponent").Wrap(err)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func decodeEd25519PublicKey(coseKey *COSEKey) (ed25519.PublicKey, error) {
	var kBytes []byte
	if err := cbor.Unmarshal(coseKey.CrvOrNOrK, &kBytes); err != nil {
		return nil, NewError("Error unmarshaling Ed25519 public key").Wrap(err)
	}

	k := ed25519.PublicKey(kBytes)
	return k, nil
}
