package warp

/*
//FinishRegistration accepts the authenticator attestation response and
//extension client outputs and validates the
func FinishRegistration(
	sess *SessionData,
	cred PublicKeyAttestationCredential,
	extValidators ...ExtensionValidator,
) (
	*Credential,
	error,
) {
	//Steps defined in §7.1

	//1. Let JSONtext be the result of running UTF-8 decode on the value of
	//response.clientDataJSON.
	//TODO research if there are any instances where the byte stream is not
	//valid JSON per the JSON decoder

	//2. Let C, the client data claimed as collected during the credential
	//creation, be the result of running an implementation-specific JSON parser
	//on JSONtext.
	C := CollectedClientData{}
	err := json.Unmarshal(cred.Response.ClientDataJSON, &C)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Unmarshal client data",
			Err:    &ErrUnmarshalClientData{Detail: err.Error()},
		}
	}

	//3. Verify that the value of C.type is webauthn.create.
	if C.Type != "webauthn.create" {
		return nil, &ErrValidateRegistration{
			Detail: "C.type is not webauthn.create",
		}
	}

	//4. Verify that the value of C.challenge matches the challenge that was
	//sent to the authenticator in the create() call.
	rawChallenge, err := base64.RawURLEncoding.DecodeString(C.Challenge)
	if err != nil {
		return nil, &ErrValidateRegistration{
			Detail: "Decode challenge",
			Err:    &ErrUnmarshalClientData{Detail: err.Error()},
		}
	}
	if !bytes.Equal(rawChallenge, sess.CreationOptions.Challenge) {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Challenge mismatch: got [% X] expected [% X]", rawChallenge, sess.CreationOptions.Challenge),
		}
	}

	//5. Verify that the value of C.origin matches the Relying Party's origin.
	if !strings.EqualFold(C.Origin, sess.Origin) {
		return nil, &ErrValidateRegistration{
			Detail: fmt.Sprintf("Origin mismatch: got %s expected %s", C.Origin, sess.Origin),
		}
	}

	//6. Verify that the value of C.tokenBinding.status matches the state of
	//Token Binding for the TLS connection over which the assertion was
	//obtained. If Token Binding was used on that TLS connection, also verify
	//that C.tokenBinding.id matches the base64url encoding of the Token Binding
	//ID for the connection.
	if C.TokenBinding != nil {
		switch C.TokenBinding.Status {
		case TokenBindingStatusSupported:
		case TokenBindingStatusPresent:
			if C.TokenBinding.ID == "" {
				return nil, &ErrValidateRegistration{
					Detail: "Token binding status present without ID",
				}
				//TODO implement Token Binding validation when support exists in
				//Golang standard library
			}
		default:
			return nil, &ErrValidateRegistration{
				Detail: fmt.Sprintf("Invalid token binding status %s", C.TokenBinding.Status),
			}
		}
	}

	//7. Compute the hash of response.clientDataJSON using SHA-256.
	_ = sha256.Sum256(cred.Response.ClientDataJSON)

	//8. Perform CBOR decoding on the attestationObject field of the
	//AuthenticatorAttestationResponse structure to obtain the attestation
	//statement format fmt, the authenticator data authData, and the attestation
	//statement attStmt.
	attestationObj := AttestationObject{}
	err = cbor.Unmarshal(cred.Response.AttestationObject, &attestationObj)
	if err != nil {
		return nil, &ErrValidateRegistration{Err: err}
	}
	var authData AuthenticatorData
	err = authData.Decode(bytes.NewBuffer(attestationObj.AuthData))
	if err != nil {
		return nil, &ErrValidateRegistration{Err: err}
	}
	log.Printf("%#v", authData)

	//9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
	//expected by the Relying Party.
	rpIDHash := sha256.Sum256([]byte(sess.CreationOptions.RP.ID))
	if !bytes.Equal(rpIDHash[:], authData.RPIDHash[:]) {
		return nil, &ErrValidateRegistration{Detail: fmt.Sprintf("RPID hash does not match authData (RPID: %s)", sess.CreationOptions.RP.ID)}
	}

	//10. Verify that the User Present bit of the flags in authData is set.
	if !authData.UP {
		return nil, &ErrValidateRegistration{Detail: "User Presennt bit not set"}
	}

	//11. If user verification is required for this registration, verify that
	//the User Verified bit of the flags in authData is set.
	if sess.CreationOptions.AuthenticatorSelection != nil &&
		sess.CreationOptions.AuthenticatorSelection.UserVerification == UserVerificationRequirementRequired {
		if !authData.UV {
			return nil, &ErrValidateRegistration{Detail: "User Verification required but missing"}
		}
	}

	return nil, nil
}
*/
