package warp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"testing"
)

var goodP256Key *ecdsa.PrivateKey
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

	os.Exit(m.Run())
}
