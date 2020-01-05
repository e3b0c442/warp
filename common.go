package warp

import "crypto/rand"

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
