package warp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor"
)

func TestVerifySignature(t *testing.T) {
	type verifyTest struct {
		Name      string
		COSEKey   *COSEKey
		RawKey    cbor.RawMessage
		PrivKey   interface{}
		Hash      crypto.Hash
		MangleSig bool
		IsRSAPSS  bool
		Err       error
	}

	goodP256X, _ := cbor.Marshal(goodP256Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP256Y, _ := cbor.Marshal(goodP256Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good1024N, _ := cbor.Marshal(good1024Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good1024EBuf := &bytes.Buffer{}
	binary.Write(good1024EBuf, binary.BigEndian, int32(good1024Key.PublicKey.E))
	good1024E, _ := cbor.Marshal(good1024EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good25519X, _ := cbor.Marshal(good25519Pub, cbor.EncOptions{Sort: cbor.SortCTAP2})

	tests := []verifyTest{
		{
			Name:    "Invalid CBOR",
			RawKey:  []byte{0x42, 0x00},
			PrivKey: good25519Priv,
			Err:     ErrVerifySignature,
		},
		{
			Name:    "Bad key",
			RawKey:  []byte{0xa0},
			PrivKey: good25519Priv,
			Err:     ErrVerifySignature,
		},
		{
			Name: "Wrong key type for ECDSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmES256),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey: goodP256Key,
			Hash:    crypto.SHA256,
			Err:     ErrVerifySignature,
		},
		{
			Name: "Good ES256",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmES256),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey: goodP256Key,
			Hash:    crypto.SHA256,
		},
		{
			Name: "Bad ES256",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmES256),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey:   goodP256Key,
			Hash:      crypto.SHA256,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good ES384",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmES384),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey: goodP256Key,
			Hash:    crypto.SHA384,
		},
		{
			Name: "Bad ES384",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmES384),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey:   goodP256Key,
			Hash:      crypto.SHA384,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good ES512",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmES512),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey: goodP256Key,
			Hash:    crypto.SHA512,
		},
		{
			Name: "Bad ES512",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmES512),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey:   goodP256Key,
			Hash:      crypto.SHA512,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Wrong key type for RSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				Alg:       int(AlgorithmRS1),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
			PrivKey: good1024Key,
			Hash:    crypto.SHA1,
			Err:     ErrVerifySignature,
		},
		{
			Name: "Good RS1",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS1),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey: good1024Key,
			Hash:    crypto.SHA1,
		},
		{
			Name: "Bad RS1",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS1),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA1,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good RS256",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS256),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey: good1024Key,
			Hash:    crypto.SHA256,
		},
		{
			Name: "Bad RS256",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS256),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA256,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good RS384",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS384),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey: good1024Key,
			Hash:    crypto.SHA384,
		},
		{
			Name: "Bad RS384",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS384),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA384,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good RS512",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS512),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey: good1024Key,
			Hash:    crypto.SHA512,
		},
		{
			Name: "Bad RS512",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmRS512),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA512,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good PS256",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmPS256),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:  good1024Key,
			Hash:     crypto.SHA256,
			IsRSAPSS: true,
		},
		{
			Name: "Bad PS256",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmPS256),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA256,
			IsRSAPSS:  true,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good PS384",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmPS384),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:  good1024Key,
			Hash:     crypto.SHA384,
			IsRSAPSS: true,
		},
		{
			Name: "Bad PS384",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmPS384),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA384,
			MangleSig: true,
			IsRSAPSS:  true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Good PS512",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmPS512),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:  good1024Key,
			Hash:     crypto.SHA512,
			IsRSAPSS: true,
		},
		{
			Name: "Bad PS512",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmPS512),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey:   good1024Key,
			Hash:      crypto.SHA512,
			MangleSig: true,
			IsRSAPSS:  true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Wrong key type for EdDSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				Alg:       int(AlgorithmEdDSA),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			PrivKey: good25519Priv,
			Err:     ErrVerifySignature,
		},
		{
			Name: "Good EdDSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeOKP),
				Alg:       int(AlgorithmEdDSA),
				CrvOrNOrK: []byte{0x06},
				XOrE:      good25519X,
			},
			PrivKey: good25519Priv,
		},
		{
			Name: "Bad EdDSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeOKP),
				Alg:       int(AlgorithmEdDSA),
				CrvOrNOrK: []byte{0x06},
				XOrE:      good25519X,
			},
			PrivKey:   good25519Priv,
			MangleSig: true,
			Err:       ErrVerifySignature,
		},
		{
			Name: "Bad algorithm",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeOKP),
				Alg:       -4096,
				CrvOrNOrK: []byte{0x06},
				XOrE:      good25519X,
			},
			PrivKey: good25519Priv,
			Err:     ErrVerifySignature,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			msg := []byte("I've got a lovely bunch of coconuts")
			var sig []byte
			var err error

			switch k := test.PrivKey.(type) {
			case *ecdsa.PrivateKey:
				h := test.Hash.New()
				h.Write(msg)
				r, s, err := ecdsa.Sign(rand.Reader, k, h.Sum(nil))
				if err != nil {
					tt.Fatalf("Error signing ECDSA: %v", err)
				}
				sig, err = asn1.Marshal(struct {
					R, S *big.Int
				}{R: r, S: s})
				if err != nil {
					tt.Fatalf("Error marshaling ECDSA signature: %v", err)
				}
			case *rsa.PrivateKey:
				h := test.Hash.New()
				h.Write(msg)
				if test.IsRSAPSS {
					sig, err = rsa.SignPSS(rand.Reader, k, test.Hash, h.Sum(nil), nil)
					if err != nil {
						tt.Fatalf("Error signing RSA-PSS: %v", err)
					}
				} else {
					sig, err = rsa.SignPKCS1v15(rand.Reader, k, test.Hash, h.Sum(nil))
					if err != nil {
						tt.Fatalf("Error signing RSA-PKCS1v15: %v", err)
					}
				}
			case ed25519.PrivateKey:
				sig = ed25519.Sign(k, msg)
			}

			var rawKey cbor.RawMessage
			if test.RawKey != nil {
				rawKey = test.RawKey
			} else {
				rawKey, err = cbor.Marshal(test.COSEKey, cbor.EncOptions{Sort: cbor.SortCTAP2})
				if err != nil {
					t.Fatalf("Error marshaling test key: %v", err)
				}
			}

			if test.MangleSig {
				b := make([]byte, len(sig))
				rand.Read(b)
				for i := range b {
					sig[i] = sig[i] ^ b[i]
				}
			}

			err = VerifySignature(rawKey, msg, sig)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
		})
	}
}

func TestDecodePublicKey(t *testing.T) {
	type decodeTest struct {
		Name    string
		COSEKey *COSEKey
		Err     error
	}

	goodP256X, _ := cbor.Marshal(goodP256Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP256Y, _ := cbor.Marshal(goodP256Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good1024N, _ := cbor.Marshal(good1024Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good1024EBuf := &bytes.Buffer{}
	binary.Write(good1024EBuf, binary.BigEndian, int32(good1024Key.PublicKey.E))
	good1024E, _ := cbor.Marshal(good1024EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good25519X, _ := cbor.Marshal(good25519Pub, cbor.EncOptions{Sort: cbor.SortCTAP2})

	tests := []decodeTest{
		{
			Name: "Bad algorithm",
			COSEKey: &COSEKey{
				Alg: -4096,
			},
			Err: ErrDecodeCOSEKey,
		},
		{
			Name: "Bad RSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				CrvOrNOrK: []byte{0xa0},
			},
			Err: ErrDecodeCOSEKey,
		},
		{
			Name: "Good RSA",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeRSA),
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
		},
		{
			Name: "Bad EC2",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				CrvOrNOrK: []byte{0xa0},
			},
			Err: ErrDecodeCOSEKey,
		},
		{
			Name: "Good EC2",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeEC2),
				CrvOrNOrK: []byte{0x01},
				XOrE:      goodP256X,
				Y:         goodP256Y,
			},
		},
		{
			Name: "Bad OKP",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeOKP),
				CrvOrNOrK: []byte{0xa0},
			},
			Err: ErrDecodeCOSEKey,
		},
		{
			Name: "Good OKP",
			COSEKey: &COSEKey{
				Kty:       int(KeyTypeOKP),
				CrvOrNOrK: []byte{0x06},
				XOrE:      []byte(good25519X),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			k, err := DecodePublicKey(test.COSEKey)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if k == nil {
				tt.Fatalf("Key is nil with no error")
			}
		})
	}
}

func TestDecodeECDSAPublicKey(t *testing.T) {
	type decodeECDSATest struct {
		Name      string
		COSEKey   *COSEKey
		KeyTester *ecdsa.PrivateKey
		Err       error
	}

	goodP256X, _ := cbor.Marshal(goodP256Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP256Y, _ := cbor.Marshal(goodP256Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	goodP384X, _ := cbor.Marshal(goodP384Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP384Y, _ := cbor.Marshal(goodP384Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	goodP521X, _ := cbor.Marshal(goodP521Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	goodP521Y, _ := cbor.Marshal(goodP521Key.PublicKey.Y.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

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

func TestDecodeRSAPublicKey(t *testing.T) {
	type decodeRSATest struct {
		Name      string
		COSEKey   *COSEKey
		KeyTester *rsa.PrivateKey
		Err       error
	}

	good1024N, _ := cbor.Marshal(good1024Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good1024EBuf := &bytes.Buffer{}
	binary.Write(good1024EBuf, binary.BigEndian, int32(good1024Key.PublicKey.E))
	good1024E, _ := cbor.Marshal(good1024EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good2048N, _ := cbor.Marshal(good2048Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good2048EBuf := &bytes.Buffer{}
	binary.Write(good2048EBuf, binary.BigEndian, int32(good2048Key.PublicKey.E))
	good2048E, _ := cbor.Marshal(good2048EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good4096N, _ := cbor.Marshal(good4096Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good4096EBuf := &bytes.Buffer{}
	binary.Write(good4096EBuf, binary.BigEndian, int32(good4096Key.PublicKey.E))
	good4096E, _ := cbor.Marshal(good4096EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	tests := []decodeRSATest{
		{
			Name: "Missing modulus",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{},
			},
			Err: NewError("Error unmarshaling RSA modulus"),
		},
		{
			Name: "Malformed modulus",
			COSEKey: &COSEKey{
				CrvOrNOrK: []byte{0x61, 0x80},
			},
			Err: NewError("Error unmarshaling RSA modulus"),
		},
		{
			Name: "Missing exponent",
			COSEKey: &COSEKey{
				CrvOrNOrK: good2048N,
				XOrE:      []byte{},
			},
			Err: NewError("Error unmarshaling RSA exponent"),
		},
		{
			Name: "Malformed exponent",
			COSEKey: &COSEKey{
				CrvOrNOrK: good2048N,
				XOrE:      []byte{0x61, 0x80},
			},
			Err: NewError("Error unmarshaling RSA exponent"),
		},
		{
			Name: "Wrong exponent type",
			COSEKey: &COSEKey{
				CrvOrNOrK: good2048N,
				XOrE:      []byte{0x43, 0x01, 0x02, 0x03},
			},
			Err: NewError("Error decoding RSA exponent"),
		},
		{
			Name: "Good 1024",
			COSEKey: &COSEKey{
				CrvOrNOrK: good1024N,
				XOrE:      good1024E,
			},
			KeyTester: good1024Key,
		},
		{
			Name: "Good 2048",
			COSEKey: &COSEKey{
				CrvOrNOrK: good2048N,
				XOrE:      good2048E,
			},
			KeyTester: good2048Key,
		},
		{
			Name: "Good 4096",
			COSEKey: &COSEKey{
				CrvOrNOrK: good4096N,
				XOrE:      good4096E,
			},
			KeyTester: good4096Key,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			k, err := decodeRSAPublicKey(test.COSEKey)
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

			sig, err := rsa.SignPKCS1v15(rand.Reader, test.KeyTester, crypto.SHA256, hashed)
			if err != nil {
				tt.Fatalf("Unable to sign test message: %v", err)
			}

			err = rsa.VerifyPKCS1v15(k, crypto.SHA256, hashed, sig)
			if err != nil {
				tt.Fatalf("Public key did not decode correctly: %v", *k)
			}
		})
	}
}

func TestVerifyRSAPKCS1v15Signature(t *testing.T) {
	type verifyRSAPKCS1v15Setup struct {
		Name    string
		KeySize int
		Hash    crypto.Hash
	}

	type verifyRSAPKCS1v15Test struct {
		Name    string
		PrivKey *rsa.PrivateKey
		PubKey  *rsa.PublicKey
		Hash    crypto.Hash
		Message []byte
		Sig     []byte
		Err     error
	}

	setups := []verifyRSAPKCS1v15Setup{}
	for _, ks := range []int{1024, 2048, 4096} {
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			setups = append(setups, verifyRSAPKCS1v15Setup{Name: fmt.Sprintf("%d-%s", ks, hashName(h)), KeySize: ks, Hash: h})
		}
	}

	for _, setup := range setups {
		t.Run(setup.Name, func(tt *testing.T) {
			msg := []byte("I've got a lovely bunch of coconuts")
			priv, err := rsa.GenerateKey(rand.Reader, setup.KeySize)
			if err != nil {
				tt.Fatalf("Unable to generate setup key: %v", err)
			}

			h := setup.Hash.New()
			h.Write(msg)

			sig, err := rsa.SignPKCS1v15(rand.Reader, priv, setup.Hash, h.Sum(nil))
			if err != nil {
				tt.Fatalf("Unable to sign in setup: %v", err)
			}

			badSig := make([]byte, len(sig))
			copy(badSig, sig)
			mask := make([]byte, 1)
			for i := 0; i < len(badSig); i++ {
				rand.Read(mask)
				badSig[i] = badSig[i] ^ mask[0]
			}

			tests := []verifyRSAPKCS1v15Test{
				{
					Name:    "Good",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Message: msg,
					Sig:     sig,
				},
				{
					Name:    "Empty sig",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Sig:     []byte{},
					Err:     NewError("RSA signature verification failed"),
				},
				{
					Name:    "Bad sig",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Sig:     badSig,
					Err:     NewError("RSA signature verification failed"),
				},
			}

			for _, test := range tests {
				tt.Run(test.Name, func(ttt *testing.T) {
					err := verifyRSAPKCS1v15Signature(test.PubKey, test.Hash, test.Message, test.Sig)
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

func TestVerifyRSAPPSSSignature(t *testing.T) {
	type verifyRSAPSSSetup struct {
		Name    string
		KeySize int
		Hash    crypto.Hash
	}

	type verifyRSAPSSTest struct {
		Name    string
		PrivKey *rsa.PrivateKey
		PubKey  *rsa.PublicKey
		Hash    crypto.Hash
		Message []byte
		Sig     []byte
		Err     error
	}

	setups := []verifyRSAPSSSetup{}
	for _, ks := range []int{1024, 2048, 4096} {
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			setups = append(setups, verifyRSAPSSSetup{Name: fmt.Sprintf("%d-%s", ks, hashName(h)), KeySize: ks, Hash: h})
		}
	}

	for _, setup := range setups {
		t.Run(setup.Name, func(tt *testing.T) {
			msg := []byte("I've got a lovely bunch of coconuts")
			priv, err := rsa.GenerateKey(rand.Reader, setup.KeySize)
			if err != nil {
				tt.Fatalf("Unable to generate setup key: %v", err)
			}

			h := setup.Hash.New()
			h.Write(msg)

			sig, err := rsa.SignPSS(rand.Reader, priv, setup.Hash, h.Sum(nil), nil)
			if err != nil {
				tt.Fatalf("Unable to sign in setup: %v", err)
			}

			badSig := make([]byte, len(sig))
			copy(badSig, sig)
			mask := make([]byte, 1)
			for i := 0; i < len(badSig); i++ {
				rand.Read(mask)
				badSig[i] = badSig[i] ^ mask[0]
			}

			tests := []verifyRSAPSSTest{
				{
					Name:    "Good",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Message: msg,
					Sig:     sig,
				},
				{
					Name:    "Empty sig",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Sig:     []byte{},
					Err:     NewError("RSA signature verification failed"),
				},
				{
					Name:    "Bad sig",
					PrivKey: priv,
					PubKey:  &priv.PublicKey,
					Hash:    setup.Hash,
					Sig:     badSig,
					Err:     NewError("RSA signature verification failed"),
				},
			}

			for _, test := range tests {
				tt.Run(test.Name, func(ttt *testing.T) {
					err := verifyRSAPSSSignature(test.PubKey, test.Hash, test.Message, test.Sig)
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

func TestDecodeEd25519PublicKey(t *testing.T) {
	type decodeEd25519Test struct {
		Name      string
		COSEKey   *COSEKey
		KeyTester ed25519.PrivateKey
		Err       error
	}

	goodKeyX, err := cbor.Marshal(good25519Pub, cbor.EncOptions{Sort: cbor.SortCTAP2})
	if err != nil {
		t.Fatalf("Error marshalig pubkey: %v", err)
	}

	tests := []decodeEd25519Test{
		{
			Name: "Missing public key",
			COSEKey: &COSEKey{
				XOrE: []byte{},
			},
			Err: NewError("Error unmarshaling Ed25519 public key"),
		},
		{
			Name: "Malformed public key",
			COSEKey: &COSEKey{
				XOrE: []byte{0x61, 0x80},
			},
			Err: NewError("Error unmarshaling Ed25519 public key"),
		},
		{
			Name: "Good",
			COSEKey: &COSEKey{
				//CrvOrNOrK: []byte{0x06},
				XOrE: goodKeyX,
			},
			KeyTester: good25519Priv,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			k, err := decodeEd25519PublicKey(test.COSEKey)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if k == nil {
				tt.Fatalf("parsed key is nil without error")
			}

			msg := []byte("I've got a lovely bunch of coconuts")
			sig := ed25519.Sign(test.KeyTester, msg)

			good := ed25519.Verify(k, msg, sig)
			if !good {
				tt.Fatalf("Public keey did not decode correctly: %v", k)
			}
		})
	}
}
