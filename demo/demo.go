package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/e3b0c442/warp"
)

type user struct {
	name string
	id   []byte
}

func (u *user) UserID() []byte {
	return u.id
}

func (u *user) UserName() string {
	return u.name
}

func (u *user) UserDisplayName() string {
	return u.name
}

func (u *user) UserIcon() string {
	return ""
}

type rp struct {
	origin string
}

func (r rp) RelyingPartyID() string {
	u, _ := url.Parse(r.origin)
	return u.Hostname()
}

func (r rp) RelyingPartyName() string {
	return r.origin
}
func (r rp) RelyingPartyIcon() string {
	return ""
}
func (r rp) RelyingPartyOrigin() string {
	return r.origin
}

type SessionData struct {
	CreationOptions *warp.PublicKeyCredentialCreationOptions
}

var users map[string]*user
var relyingParty rp
var sessions map[string]SessionData

var (
	bind   string
	origin string
	cert   string
	key    string
)

func init() {
	flag.StringVar(&bind, "bind", ":3001", "Bind address/port (default: \":3001\")")
	flag.StringVar(&origin, "origin", "https://localhost:3001", "Fully qualified origin (default: \"https://localhost:3001\")")
	flag.StringVar(&cert, "cert", "", "Path to TLS certificate (default: \"\")")
	flag.StringVar(&key, "key", "", "Path to TLS key (default: \"\")")
}

func main() {
	flag.Parse()

	if (cert == "" && key != "") || (cert != "" && key == "") {
		log.Fatal("Must provide neither or both of key and cert")
	}

	if cert == "" {
		tmpDir, err := ioutil.TempDir("", "")
		if err != nil {
			log.Fatalf("Unable to create temp cert dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		cert, key, err = tmpCert(tmpDir)
		if err != nil {
			log.Fatalf("Unable to create temp cert/key: %v", err)
		}
	}

	relyingParty = rp{
		origin: origin,
	}
	users = make(map[string]*user)
	sessions = make(map[string]SessionData)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		index, err := ioutil.ReadFile("./static/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(index)
	})
	http.HandleFunc("/register/start", startRegistration)
	http.HandleFunc("/register/finish", finishRegistration)

	log.Fatal(http.ListenAndServeTLS(bind, cert, key, nil))
}

func startRegistration(w http.ResponseWriter, r *http.Request) {
	usernames, ok := r.URL.Query()["username"]
	if !ok || len(usernames) == 0 || usernames[0] == "" {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	username := usernames[0]

	var u *user
	if u, ok = users[username]; !ok {
		u = &user{
			name: username,
		}

		u.id = make([]byte, 16)
		rand.Read(u.id)
		users[username] = u
	}

	opts, err := warp.StartRegistration(relyingParty, u, warp.Attestation(warp.ConveyanceIndirect))
	if err != nil {
		http.Error(w, fmt.Sprintf("Start register fail: %v", err), http.StatusInternalServerError)
		return
	}

	sessions[username] = SessionData{
		CreationOptions: opts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(opts)
}

func finishRegistration(w http.ResponseWriter, r *http.Request) {
	usernames, ok := r.URL.Query()["username"]
	if !ok || len(usernames) == 0 || usernames[0] == "" {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	username := usernames[0]
	if !ok {
		http.Error(w, fmt.Sprintf("No session found for %s", username), http.StatusBadRequest)
		return
	}

	cred := warp.AttestationPublicKeyCredential{}
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		http.Error(w, fmt.Sprintf("Decode credential fail: %v", err), http.StatusBadRequest)
		return
	}

	session, ok := sessions[username]
	if !ok {
		http.Error(w, fmt.Sprintf("Session missing for user %s", username), http.StatusUnauthorized)
		return
	}

	_, err = warp.FinishRegistration(relyingParty, session.CreationOptions, &cred)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		for err != nil {
			log.Printf("%v", err)
			if e, ok := err.(warp.DetailedError); ok {
				log.Printf("%s", e.Details())
			}
			err = errors.Unwrap(err)
		}

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func tmpCert(tmpDir string) (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", err
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{originURL.Hostname()},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certOut, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return "", "", err
	}
	certOut.Close()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyOut, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return "", "", err
	}
	keyOut.Close()

	return certOut.Name(), keyOut.Name(), nil
}
