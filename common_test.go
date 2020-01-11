package warp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

type badReader struct{}

func (*badReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrNoProgress
}

func TestGenerateChallenge(t *testing.T) {
	type challengeTest struct {
		Name        string
		AltReader   io.Reader
		AltLen      int
		ExpectedLen int
		Err         error
	}

	tests := []challengeTest{
		{
			Name:        "Good",
			ExpectedLen: ChallengeLength,
		},
		{
			Name:      "Bad reader",
			AltReader: &badReader{},
			Err:       io.ErrNoProgress,
		},
		{
			Name:      "Not enough bytes",
			AltReader: bytes.NewBuffer([]byte{1, 2, 3, 4, 5}),
			AltLen:    10,
			Err:       NewError("Read %d random bytes, needed %d", 5, 10),
		},
		{
			Name:        "Plenty of bytes",
			AltReader:   bytes.NewBuffer([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
			ExpectedLen: 5,
			AltLen:      5,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			if test.AltReader != nil {
				randReader = test.AltReader
				defer func() { randReader = rand.Reader }()
			}

			if test.AltLen != 0 {
				oldLen := ChallengeLength
				ChallengeLength = test.AltLen
				defer func() { ChallengeLength = oldLen }()
			}

			chal, err := generateChallenge()
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}

			if len(chal) != test.ExpectedLen {
				tt.Fatalf("Expected %d bytes, got %d", test.ExpectedLen, len(chal))
			}
		})
	}

}
