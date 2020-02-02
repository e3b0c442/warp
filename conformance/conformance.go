package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

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
	displayName string
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
	return u.displayName
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
)

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func init() {
	flag.StringVar(&bind, "bind", LookupEnvOrString("BIND", ":3001"), "Bind address/port (default: \":3001\")")
	flag.StringVar(&origin, "origin", LookupEnvOrString("ORIGIN", "https://localhost:3001"), "Fully qualified origin (default: \"https://localhost:3001\")")
	flag.StringVar(&cert, "cert", LookupEnvOrString("CERT", ""), "Path to TLS certificate (default: \"\")")
	flag.StringVar(&key, "key", LookupEnvOrString("KEY", ""), "Path to TLS key (default: \"\")")
}

func main() {
	flag.Parse()

	if (cert == "" && key != "") || (cert != "" && key == "") {
		log.Fatal("Must provide neither or both of key and cert")
	}

	relyingParty = rp{
		origin: origin,
	}
	users = make(map[string]warp.User)
	credentials = make(map[string]warp.Credential)
	sessions = make(map[string]sessionData)

	http.HandleFunc("/attestation/options", attestationOptions)

	if cert == "" {
		log.Fatal(http.ListenAndServe(bind, nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(bind, cert, key, nil))
	}
}

type attestationOptionsBody struct {
	Username               string `json:"username"`
	DisplayName            string `json:"displayName"`
	AuthenticatorSelection struct {
		RequireResidentKey bool   `json:"requireResidentKey"`
		UserVerification   string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Attestation string                 `json:"attestation"`
	Extensions  map[string]interface{} `json:"extensions"`
}

func attestationOptions(w http.ResponseWriter, r *http.Request) {
	var body attestationOptionsBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	var u *user
	if uu, ok := users[body.Username]; !ok {
		u = &user{
			name:        body.Username,
			displayName: body.DisplayName,
			id:          make([]byte, 16),
			credentials: make(map[string]warp.Credential),
		}

		rand.Read(u.id)
		users[body.Username] = u
	} else {
		u = uu.(*user)
	}

	addOpts := []warp.Option{
		warp.AuthenticatorSelection(
			warp.AuthenticatorSelectionCriteria{
				RequireResidentKey: body.AuthenticatorSelection.RequireResidentKey,
				UserVerification: warp.UserVerificationRequirement(
					body.AuthenticatorSelection.UserVerification,
				),
			},
		),
		warp.Attestation(warp.AttestationConveyancePreference(body.Attestation)),
		warp.Extensions(
			[]warp.Extension{
				func(aeci warp.AuthenticationExtensionsClientInputs) {
					for k, v := range body.Extensions {
						aeci[k] = v
					}
					return
				},
			}...,
		),
	}

	opts, err := warp.StartRegistration(relyingParty, u, addOpts...)
	if err != nil {
		http.Error(w, fmt.Sprintf("Start register fail: %v", err), http.StatusInternalServerError)
		return
	}

	sessions[body.Username] = sessionData{
		CreationOptions: opts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(opts)
}
