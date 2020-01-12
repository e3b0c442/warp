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

	good2048Key, err := rsa.GenerateKey(rand.Reader, 2048)
	good2048N, err := cbor.Marshal(good2048Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good2048EBuf := &bytes.Buffer{}
	err = binary.Write(good2048EBuf, binary.BigEndian, int32(good2048Key.PublicKey.E))
	if err != nil {
		t.Fatal(err)
	}
	good2048E, err := cbor.Marshal(good2048EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	good4096Key, err := rsa.GenerateKey(rand.Reader, 4096)
	good4096N, err := cbor.Marshal(good4096Key.PublicKey.N.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	good4096EBuf := &bytes.Buffer{}
	err = binary.Write(good4096EBuf, binary.BigEndian, int32(good4096Key.PublicKey.E))
	if err != nil {
		t.Fatal(err)
	}
	good4096E, err := cbor.Marshal(good4096EBuf.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})

	if err != nil {
		t.Fatalf("Unable to initialize testing keys")
	}

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

	goodKeyPub, goodKeyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Unable to initialize testing key")
	}
	goodKeyX, err := cbor.Marshal(goodKeyPub, cbor.EncOptions{Sort: cbor.SortCTAP2})

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
			KeyTester: goodKeyPriv,
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
