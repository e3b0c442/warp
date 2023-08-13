package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/e3b0c442/warp"
)

type Base64URLBytes []byte

func (b Base64URLBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *Base64URLBytes) UnmarshalJSON(data []byte) error {
	bb := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)-2))
	_, err := base64.RawURLEncoding.Decode(bb, data[1:len(data)-1])
	*b = Base64URLBytes(bb)
	return err
}

type ServerResponse struct {
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage"`
}

type ServerPublicKeyCredentialCreationOptionsRequest struct {
	Username               string                                    `json:"username"`
	DisplayName            string                                    `json:"displayName"`
	AuthenticatorSelection warp.AuthenticatorSelectionCriteria       `json:"authenticatorSelection"`
	Attestation            warp.AttestationConveyancePreference      `json:"attestation"`
	Extensions             warp.AuthenticationExtensionsClientInputs `json:"extensions"`
}

type ServerPublicKeyCredentialUserEntity struct {
	warp.PublicKeyCredentialEntity
	ID          Base64URLBytes `json:"id"`
	DisplayName string         `json:"displayName"`
}

type ServerPublicKeyCredentialCreationOptionsResponse struct {
	ServerResponse
	RP                     warp.PublicKeyCredentialRPEntity          `json:"rp"`
	User                   ServerPublicKeyCredentialUserEntity       `json:"user"`
	Challenge              Base64URLBytes                            `json:"challenge"`
	PubKeyCredParams       []warp.PublicKeyCredentialParameters      `json:"pubKeyCredParams"`
	Timeout                uint64                                    `json:"timeout"`
	ExcludeCredentials     []warp.PublicKeyCredentialDescriptor      `json:"excludeCredentials"`
	AuthenticatorSelection warp.AuthenticatorSelectionCriteria       `json:"authenticatorSelection"`
	Attestation            warp.AttestationConveyancePreference      `json:"attestation"`
	Extensions             warp.AuthenticationExtensionsClientInputs `json:"extensions"`
}

func AttestationOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ServerResponse{Status: "failed", ErrorMessage: "Method not allowed"})
		return
	}

	buf := &bytes.Buffer{}
	io.Copy(buf, r.Body)
	log.Printf("/attestation/options request: %s", buf.String())

	var request ServerPublicKeyCredentialCreationOptionsRequest
	if err := json.NewDecoder(buf).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ServerResponse{Status: "failed", ErrorMessage: "Bad request"})
		return
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)

	var response ServerPublicKeyCredentialCreationOptionsResponse = ServerPublicKeyCredentialCreationOptionsResponse{
		ServerResponse: ServerResponse{Status: "ok"},
		RP: warp.PublicKeyCredentialRPEntity{
			PublicKeyCredentialEntity: warp.PublicKeyCredentialEntity{
				Name: "Test",
			},
			ID: "localhost",
		},
		User: ServerPublicKeyCredentialUserEntity{
			PublicKeyCredentialEntity: warp.PublicKeyCredentialEntity{
				Name: request.Username,
			},
			ID:          Base64URLBytes("1234"),
			DisplayName: request.DisplayName,
		},
		Challenge: challenge,
		PubKeyCredParams: []warp.PublicKeyCredentialParameters{
			{
				Type: "public-key",
				Alg:  warp.AlgorithmES256,
			},
		},
		Timeout:                60000,
		AuthenticatorSelection: request.AuthenticatorSelection,
		Attestation:            request.Attestation,
		Extensions:             request.Extensions,
	}

	buf.Reset()
	json.NewEncoder(buf).Encode(response)
	log.Printf("/attestation/options response: %s", buf.String())

	io.Copy(w, buf)
}
