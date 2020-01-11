package warp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/fxamacker/cbor"
)

func TestDecodeECDSAPublicKey(t *testing.T) {
	type decodeECDSATest struct {
		Name      string
		COSEKey   *COSEKey
		KeyTester *ecdsa.PrivateKey
		Err       error
	}

	goodP256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	goodP256X, err := cbor.Marshal(goodP256Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP256Y, err := cbor.Marshal(goodP256Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	if err != nil {
		t.Fatalf("Unable to generate P256 key")
	}

	tests := []decodeECDSATest{
		{
			Name: "Missing curve",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{},
			},
			Err: NewError("Error decoding elliptic curve ID"),
		},
		{
			Name: "Malformed curve",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x41, 0x80},
			},
			Err: NewError("Error decoding elliptic curve ID"),
		},
		{
			Name: "Invalid curve ID",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x0}, //Invalid curve (ID 0)
			},
			Err: NewError("COSE elliptic curve 0 not supported"),
		},
		{
			Name: "Missing elliptic X",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x1}, //CurveP256
				XOrE:      []byte{},
			},
			Err: NewError("Error decoding elliptic X parameter"),
		},
		{
			Name: "Malformed elliptic X",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x1}, //CurveP256
				XOrE:      []byte{0x61, 0x80},
			},
			Err: NewError("Error decoding elliptic X parameter"),
		},
		{
			Name: "Missing elliptic Y",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x1}, //CurveP256
				XOrE:      goodP256X,
				Y:         []byte{},
			},
			Err: NewError("Error decoding elliptic Y parameter"),
		},
		{
			Name: "Malformed elliptic Y",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x1}, //CurveP256
				XOrE:      goodP256X,
				Y:         []byte{0x61, 0x80},
			},
			Err: NewError("Error decoding elliptic Y parameter"),
		},
		{
			Name: "Good",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x1}, //CurveP256
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			KeyTester: goodP256Key,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			k, err := decodeECDSAPublicKey(test.COSEKey)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error returned: %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if k == nil {
				tt.Fatalf("parsed key is nil without error")
			}

			h := crypto.SHA256.New()
			h.Write([]byte("I've got a lovely bunch of coconuts"))
			hashed := h.Sum(nil)

			r, s, err := ecdsa.Sign(rand.Reader, test.KeyTester, hashed)
			if err != nil {
				tt.Fatalf("Unable to sign test message: %v", err)
			}

			good := ecdsa.Verify(k, hashed, r, s)
			if !good {
				tt.Fatalf("Public key did not decode correctly")
			}
		})
	}
}
