package warp

import "bytes"

//StartAuthentication starts the authentication ceremony by creating a
//credential request options object to be sent to the client
func StartAuthentication(
	opts ...Option,
) (
	*PublicKeyCredentialRequestOptions,
	error,
) {
	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, ErrGenerateChallenge.Wrap(err)
	}

	requestOptions := PublicKeyCredentialRequestOptions{
		Challenge: challenge,
	}

	for _, opt := range opts {
		err = opt(&requestOptions)
		if err != nil {
			return nil, err
		}
	}

	return &requestOptions, nil
}

//FinishAuthentication completes the authentication ceremony by validating the
//provided credential assertion against the stored public key.
func FinishAuthentication(
	userFinder UserFinder,
	opts *PublicKeyCredentialRequestOptions,
	cred *AssertionPublicKeyCredential,
) error {
	//1. If the allowCredentials option was given when this authentication
	//ceremony was initiated, verify that credential.id identifies one of the
	//public key credentials that were listed in allowCredentials.
	if err := checkAllowedCredentials(opts.AllowCredentials, cred.RawID); err != nil {
		return ErrVerifyAuthentication.Wrap(err)
	}

	//2. Identify the user being authenticated and verify that this user is the
	//owner of the public key credential source credentialSource identified by
	//credential.id. If the user was identified before the authentication
	//ceremony was initiated, verify that the identified user is the owner of
	//credentialSource. If credential.response.userHandle is present, verify
	//that this value identifies the same user as was previously identified. If
	//the user was not identified before the authentication ceremony was
	//initiated, verify that credential.response.userHandle is present, and that
	//the user identified by this value is the owner of credentialSource.
	if err := checkUserOwnsCredential(userFinder, cred); err != nil {
		return ErrVerifyAuthentication.Wrap(err)
	}

	return nil
}

func checkAllowedCredentials(allowed []PublicKeyCredentialDescriptor, id []byte) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, cred := range allowed {
		if bytes.Equal(id, cred.ID) {
			return nil
		}
	}
	return NewError("Credential ID not found in allowed list")
}

func checkUserOwnsCredential(userFinder UserFinder, cred *AssertionPublicKeyCredential) error {
	user, err := userFinder(cred.Response.UserHandle)
	if err != nil {
		return ErrVerifyAuthentication.Wrap(err)
	}

	userCreds := user.Credentials()
	err = NewError("User %s does not own this credential", user.Name())
	for _, userCred := range userCreds {
		if bytes.Equal(cred.RawID, userCred.ID) {
			err = nil
			break
		}
	}

	return err
}
