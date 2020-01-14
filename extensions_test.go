package warp

import (
	"errors"
	"reflect"
	"testing"
)

func TestBuildExtensions(t *testing.T) {
	type buildTest struct {
		Name     string
		Exts     []Extension
		Expected AuthenticationExtensionsClientInputs
	}

	tests := []buildTest{
		{
			Name:     "empty",
			Exts:     []Extension{},
			Expected: AuthenticationExtensionsClientInputs{},
		},
		{
			Name: "appid",
			Exts: []Extension{
				UseAppID("https://e3b0c442.io"),
			},
			Expected: AuthenticationExtensionsClientInputs{
				"appid": "https://e3b0c442.io",
			},
		},
		{
			Name: "appid + adhoc",
			Exts: []Extension{
				UseAppID("https://e3b0c442.io"),
				func(e AuthenticationExtensionsClientInputs) {
					e["random"] = "modnar"
				},
			},
			Expected: AuthenticationExtensionsClientInputs{
				"appid":  "https://e3b0c442.io",
				"random": "modnar",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			aeci := BuildExtensions(test.Exts...)
			if !reflect.DeepEqual(aeci, test.Expected) {
				tt.Fatalf("Output does not match expected")
			}
		})
	}
}

func TestUseAppID(t *testing.T) {
	type appIDTest struct {
		Name     string
		AppID    string
		Expected AuthenticationExtensionsClientInputs
	}

	tests := []appIDTest{
		{
			Name:  "empty",
			AppID: "",
			Expected: AuthenticationExtensionsClientInputs{
				"appid": "",
			},
		},
		{
			Name:  "real",
			AppID: "https://e3b0c442.io",
			Expected: AuthenticationExtensionsClientInputs{
				"appid": "https://e3b0c442.io",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ext := UseAppID(test.AppID)
			aeci := AuthenticationExtensionsClientInputs{}
			ext(aeci)
			if !reflect.DeepEqual(aeci, test.Expected) {
				tt.Fatalf("Output mismatch")
			}
		})
	}
}

func TestVerifyAppID(t *testing.T) {
	type verifyTest struct {
		Name string
		Out  interface{}
		Err  error
	}

	tests := []verifyTest{
		{
			Name: "good",
			Out:  true,
		},
		{
			Name: "bad",
			Out:  "bad",
			Err:  ErrVerifyClientExtensionOutput,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := VerifyAppID(nil, test.Out)
			if err != nil {
				if errors.Is(err, test.Err) {
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatal("Did not get expected error")
			}
		})
	}
}

func TestEffectiveRPID(t *testing.T) {
	type rpidTest struct {
		Name     string
		Opts     *PublicKeyCredentialRequestOptions
		Cred     *AssertionPublicKeyCredential
		Expected string
	}

	tests := []rpidTest{
		{
			Name: "missing in credential",
			Opts: &PublicKeyCredentialRequestOptions{
				RPID: "e3b0c442.io",
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": "https://e3b0c442.io",
				},
			},
			Cred:     &AssertionPublicKeyCredential{},
			Expected: "e3b0c442.io",
		},
		{
			Name: "wrong type in credential",
			Opts: &PublicKeyCredentialRequestOptions{
				RPID: "e3b0c442.io",
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": "https://e3b0c442.io",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": "true",
					},
				},
			},
			Expected: "e3b0c442.io",
		},
		{
			Name: "wrong value in credential",
			Opts: &PublicKeyCredentialRequestOptions{
				RPID: "e3b0c442.io",
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": "https://e3b0c442.io",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": false,
					},
				},
			},
			Expected: "e3b0c442.io",
		},
		{
			Name: "missing in options",
			Opts: &PublicKeyCredentialRequestOptions{
				RPID: "e3b0c442.io",
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
			},
			Expected: "e3b0c442.io",
		},
		{
			Name: "wrong type in options",
			Opts: &PublicKeyCredentialRequestOptions{
				RPID: "e3b0c442.io",
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": 3,
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": "true",
					},
				},
			},
			Expected: "e3b0c442.io",
		},
		{
			Name: "good",
			Opts: &PublicKeyCredentialRequestOptions{
				RPID: "e3b0c442.io",
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": "https://e3b0c442.io",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
			},
			Expected: "https://e3b0c442.io",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			rpid := EffectiveRPID(test.Opts, test.Cred)
			if rpid != test.Expected {
				tt.Fatalf("Got %s expected %s", rpid, test.Expected)
			}
		})
	}

}
