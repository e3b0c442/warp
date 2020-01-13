package warp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor"
)

var goodP256Key *ecdsa.PrivateKey
var goodP256X cbor.RawMessage
var goodP256Y cbor.RawMessage
var goodP256COSE *COSEKey
var goodP256Raw cbor.RawMessage
var goodP384Key *ecdsa.PrivateKey
var goodP521Key *ecdsa.PrivateKey
var good1024Key *rsa.PrivateKey
var good2048Key *rsa.PrivateKey
var good4096Key *rsa.PrivateKey
var good25519Pub ed25519.PublicKey
var good25519Priv ed25519.PrivateKey

func TestMain(m *testing.M) {
	var err error

	goodP256Key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	goodP384Key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	goodP521Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	good1024Key, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	good2048Key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	good4096Key, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	good25519Pub, good25519Priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Key gen error: %v", err)
	}

	goodP256X, err = cbor.Marshal(goodP256Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	if err != nil {
		log.Fatalf("X marshal err: %v", err)
	}
	goodP256Y, err = cbor.Marshal(goodP256Key.PublicKey.X.Bytes(), cbor.EncOptions{Sort: cbor.SortCTAP2})
	if err != nil {
		log.Fatalf("Y marshal err: %v", err)
	}

	goodP256COSE = &COSEKey{
		Kty:       int(KeyTypeEC2),
		Alg:       int(AlgorithmES256),
		CrvOrNOrK: []byte{1},
		XOrE:      goodP256X,
		Y:         goodP256Y,
	}

	goodP256Raw, err = cbor.Marshal(goodP256COSE, cbor.EncOptions{Sort: cbor.SortCTAP2})
	if err != nil {
		log.Fatalf("COSEKey marshal err: %v", err)
	}

	os.Exit(m.Run())
}

func TestSupportedKeyAlgorithms(t *testing.T) {
	algs := SupportedKeyAlgorithms()
	if !reflect.DeepEqual(algs, []COSEAlgorithmIdentifier{
		AlgorithmEdDSA,
		AlgorithmES512,
		AlgorithmES384,
		AlgorithmES256,
		AlgorithmPS512,
		AlgorithmPS384,
		AlgorithmPS256,
		AlgorithmRS512,
		AlgorithmRS384,
		AlgorithmRS256,
		AlgorithmRS1,
	}) {
		t.Fatal("Unexpected result")
	}
}

func TestSupportedAttestationStatementFormats(t *testing.T) {
	fmts := SupportedAttestationStatementFormats()
	if !reflect.DeepEqual(fmts, []AttestationStatementFormat{
		StatementNone,
	}) {
		t.Fatal("Unexpected result")
	}
}
