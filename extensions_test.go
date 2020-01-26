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

func TestValidateAppID(t *testing.T) {
	type validateTest struct {
		Name         string
		Opts         *PublicKeyCredentialRequestOptions
		Cred         *AssertionPublicKeyCredential
		ExpectedOpts *PublicKeyCredentialRequestOptions
		Err          error
	}

	tests := []validateTest{
		{
			Name:         "Key not in cred",
			Opts:         &PublicKeyCredentialRequestOptions{},
			Cred:         &AssertionPublicKeyCredential{},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{},
		},
		{
			Name: "Key in cred but not opts",
			Opts: &PublicKeyCredentialRequestOptions{},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid output type",
			Opts: &PublicKeyCredentialRequestOptions{
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
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid input type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": 1,
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Client returned false",
			Opts: &PublicKeyCredentialRequestOptions{
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
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": "https://e3b0c442.io",
				},
			},
		},

		{
			Name: "Client returned true",
			Opts: &PublicKeyCredentialRequestOptions{
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
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"appid": "https://e3b0c442.io",
				},
				RPID: "https://e3b0c442.io",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := ValidateAppID()(test.Opts, test.Cred)
			if err != nil {
				if errors.Is(err, test.Err) {
					tt.Logf("Got expected error %v", err)
					return
				}
				tt.Fatalf("Got unexpected error %v", err)
			}
			if test.Err != nil {
				tt.Fatalf("Did not get expected error")
			}
			if !reflect.DeepEqual(test.Opts, test.ExpectedOpts) {
				tt.Fatalf("Output mismatch got %#v expected %#v", *test.Opts, *test.ExpectedOpts)
			}
		})
	}
}
