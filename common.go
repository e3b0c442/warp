package warp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

//GenerateChallenge generates a random challenge used in both the registration
//and authentictaion ceremonies
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeLength)
	n, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	if n < ChallengeLength {
		return nil, NewError("Read %d random bytes, needed %d", n, ChallengeLength)
	}

	return challenge, nil
}

//ParseClientData parses a client data JSON object into CollectedClientData
func ParseClientData(jsonText []byte) (*CollectedClientData, error) {
	C := CollectedClientData{}
	err := json.Unmarshal(jsonText, &C)
	if err != nil {
		return nil, NewError("Error unmarshaling client data JSON").Wrap(err)
	}
	return &C, nil
}

//CompareChallenge compares a challenge returned with a credential object to
//the challenge sent to the credential
func CompareChallenge(C *CollectedClientData, challenge []byte) error {
	rawChallenge, err := base64.RawURLEncoding.DecodeString(C.Challenge)
	if err != nil {
		return err
	}

	if !bytes.Equal(rawChallenge, challenge) {
		return fmt.Errorf("Challenge mismatch: got [% X] expected [% X]", rawChallenge, opts.Challenge)
	}
	return nil
}
