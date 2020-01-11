package warp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
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

	goodP384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	goodP384X, err := cbor.Marshal(goodP384Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP384Y, err := cbor.Marshal(goodP384Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	goodP521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	goodP521X, err := cbor.Marshal(goodP521Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP521Y, err := cbor.Marshal(goodP521Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	if err != nil {
		t.Fatal("Unable to initialize testing keys")
	}

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
			Name: "Good P256",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x1}, //CurveP256
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			KeyTester: goodP256Key,
		},
		{
			Name: "Good P384",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x2}, //CurveP384
				XOrE:      goodP384X,
				Y:         goodP384Y,
			},
			KeyTester: goodP384Key,
		},
		{
			Name: "Good P521",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x3}, //CurveP521
				XOrE:      goodP521X,
				Y:         goodP521Y,
			},
			KeyTester: goodP521Key,
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
				tt.Fatalf("Public key did not decode correctly: %v", *k)
			}
		})
	}
}

func hashName(c crypto.Hash) string {
	switch c {
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	case crypto.SHA1:
		return "SHA1"
	}
	return ""
}

func TestVerifyECDSASignature(t *testing.T) {
	type verifyECDSASetup struct {
		Name  string
		Curve elliptic.Curve
		Hash  crypto.Hash
	}

	type verifyECDSATest struct {
		Name    string
		PrivKey *ecdsa.PrivateKey
		PubKey  *ecdsa.PublicKey
		Hash    crypto.Hash
		Message []byte
		Sig     []byte
		Err     error
	}

	setups := []verifyECDSASetup{}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			setups = append(setups, verifyECDSASetup{Name: fmt.Sprintf("%s-%s", c.Params().Name, hashName(h)), Curve: c, Hash: h})
		}
	}

	for _, setup := range setups {
		t.Run(setup.Name, func(tt *testing.T) {
			msg := []byte("I've got a lovely bunch of coconuts")
			priv, err := ecdsa.GenerateKey(setup.Curve, rand.Reader)
			if err != nil {
				tt.Fatalf("Unable to generate setup key: %v", err)
			}

			h := setup.Hash.New()
			h.Write(msg)

			r, s, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
			if err != nil {
				tt.Fatalf("Unable to sign in setup: %v", err)
			}

			marshaledSig, err := asn1.Marshal(struct {
				R, S *big.Int
			}{R: r, S: s})
			if err != nil {
				tt.Fatalf("Unable to asn1 marshal sig: %v", err)
			}

			badSig, err := asn1.Marshal(struct {
				R, S *big.Int
			}{R: r.Div(r, big.NewInt(2)), S: s.Div(s, big.NewInt(2))})
			if err != nil {
				tt.Fatalf("Unable to asn1 marshal bad sig: %v", err)
			}

			tests := []verifyECDSATest{
				{
					Name:    "Good",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Message: msg,
					Sig:     marshaledSig,
				},
				{
					Name: "Empty sig",
					Sig:  []byte{},
					Err:  NewError("Unable to parse ECDSA signature"),
				},
				{
					Name:    "Bad sig",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Sig:     badSig,
					Err:     NewError("ECDSA signature verification failed"),
				},
			}

			for _, test := range tests {
				tt.Run(test.Name, func(ttt *testing.T) {
					err := verifyECDSASignature(test.PubKey, test.Hash, test.Message, test.Sig)
					if err != nil {
						if errors.Is(err, test.Err) {
							return
						}
						ttt.Fatalf("Unexpected error %v", err)
					}
					if test.Err != nil {
						ttt.Fatal("Did not receive expected error")
					}
				})
			}
		})
	}
}
