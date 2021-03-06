package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

type rp struct {
	origin string
}

func (r rp) EntityID() string {
	u, _ := url.Parse(r.origin)
	return u.Hostname()
}

func (r rp) EntityName() string {
	return r.origin
}
func (r rp) EntityIcon() string {
	return ""
}
func (r rp) Origin() string {
	return r.origin
}

type user struct {
	name        string
	id          []byte
	credentials map[string]warp.Credential
}

func (u *user) EntityID() []byte {
	return u.id
}

func (u *user) EntityName() string {
	return u.name
}

func (u *user) EntityDisplayName() string {
	return u.name
}

func (u *user) EntityIcon() string {
	return ""
}

func (u *user) Credentials() map[string]warp.Credential {
	return u.credentials
}

type credential struct {
	owner warp.User
	att   *warp.AttestationObject
}

func (c *credential) Owner() warp.User {
	return c.owner
}

func (c *credential) CredentialID() []byte {
	return c.att.AuthData.AttestedCredentialData.CredentialID
}

func (c *credential) CredentialPublicKey() []byte {

	return c.att.AuthData.AttestedCredentialData.CredentialPublicKey
}

func (c *credential) CredentialSignCount() uint {
	return 0
}

func findCredential(id []byte) (warp.Credential, error) {
	strID := base64.RawStdEncoding.EncodeToString(id)
	if c, ok := credentials[strID]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("no credential")
}

type sessionData struct {
	CreationOptions *warp.PublicKeyCredentialCreationOptions
	RequestOptions  *warp.PublicKeyCredentialRequestOptions
}

var users map[string]warp.User
var credentials map[string]warp.Credential
var relyingParty rp
var sessions map[string]sessionData

var (
	bind   string
	origin string
	cert   string
	key    string
	notls  bool
)

func init() {
	flag.StringVar(&bind, "bind", ":3001", "Bind address/port (default: \":3001\")")
	flag.StringVar(&origin, "origin", "https://localhost:3001", "Fully qualified origin (default: \"https://localhost:3001\")")
	flag.BoolVar(&notls, "notls", false, "don't enable TLS (e.g. run behind proxy)")
	flag.StringVar(&cert, "cert", "", "Path to TLS certificate (default: \"\")")
	flag.StringVar(&key, "key", "", "Path to TLS key (default: \"\")")
}

func main() {
	flag.Parse()

	if (cert == "" && key != "") || (cert != "" && key == "") {
		log.Fatal("Must provide neither or both of key and cert")
	}

	if cert == "" && !notls {
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
	users = make(map[string]warp.User)
	credentials = make(map[string]warp.Credential)
	sessions = make(map[string]sessionData)

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
	http.HandleFunc("/authenticate/start", startAuthentication)
	http.HandleFunc("/authenticate/finish", finishAuthentication)

	if notls {
		log.Fatal(http.ListenAndServe(bind, nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(bind, cert, key, nil))
	}
}

func startRegistration(w http.ResponseWriter, r *http.Request) {
	usernames, ok := r.URL.Query()["username"]
	if !ok || len(usernames) == 0 || usernames[0] == "" {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	username := usernames[0]

	var u *user
	if uu, ok := users[username]; !ok {
		u = &user{
			name:        username,
			id:          make([]byte, 16),
			credentials: make(map[string]warp.Credential),
		}

		rand.Read(u.id)
		users[username] = u
	} else {
		u = uu.(*user)
	}

	opts, err := warp.StartRegistration(relyingParty, u, warp.Attestation(warp.ConveyanceDirect))
	if err != nil {
		http.Error(w, fmt.Sprintf("Start register fail: %v", err), http.StatusInternalServerError)
		return
	}

	sessions[username] = sessionData{
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

	att, err := warp.FinishRegistration(relyingParty, findCredential, session.CreationOptions, &cred)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		for err != nil {
			log.Printf("%v", err)
			err = errors.Unwrap(err)
		}
		return
	}

	toStore := credential{
		att:   att,
		owner: users[username],
	}
	id := base64.RawURLEncoding.EncodeToString(att.AuthData.AttestedCredentialData.CredentialID)
	credentials[id] = &toStore
	users[username].(*user).credentials[id] = &toStore

	log.Printf("NEW CREDENTIAL: %#v", id)

	w.WriteHeader(http.StatusNoContent)
}

func startAuthentication(w http.ResponseWriter, r *http.Request) {
	usernames, ok := r.URL.Query()["username"]
	if !ok || len(usernames) == 0 || usernames[0] == "" {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	username := usernames[0]
	u, ok := users[username]
	if !ok {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	opts, err := warp.StartAuthentication(warp.AllowCredentials(
		func(user warp.User) []warp.PublicKeyCredentialDescriptor {
			ds := []warp.PublicKeyCredentialDescriptor{}
			for _, c := range user.Credentials() {
				ds = append(ds, warp.PublicKeyCredentialDescriptor{
					Type: "public-key",
					ID:   c.CredentialID(),
				})
			}
			return ds
		}(u)),
		warp.RelyingPartyID(relyingParty.EntityID()),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("Start authenticate fail: %v", err), http.StatusInternalServerError)
	}

	sessions[username] = sessionData{
		RequestOptions: opts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(opts)
}

func finishAuthentication(w http.ResponseWriter, r *http.Request) {
	usernames, ok := r.URL.Query()["username"]
	if !ok || len(usernames) == 0 || usernames[0] == "" {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	username := usernames[0]

	cred := warp.AssertionPublicKeyCredential{}
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

	_, err = warp.FinishAuthentication(
		relyingParty,
		func(_ []byte) (warp.User, error) {
			if us, ok := users[username]; ok {
				return us, nil
			}
			return nil, fmt.Errorf("user not found")
		},
		session.RequestOptions,
		&cred,
	)

	if err != nil {
		http.Error(w, fmt.Sprintf("Unauthorized: %v", err), http.StatusUnauthorized)
		for err != nil {
			log.Printf("%v", err)
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
