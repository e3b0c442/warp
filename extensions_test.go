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

func TestUseTxAuthSimple(t *testing.T) {
	type appIDTest struct {
		Name         string
		TxAuthSimple string
		Expected     AuthenticationExtensionsClientInputs
	}

	tests := []appIDTest{
		{
			Name:         "empty",
			TxAuthSimple: "",
			Expected: AuthenticationExtensionsClientInputs{
				"txAuthSimple": "",
			},
		},
		{
			Name:         "real",
			TxAuthSimple: "Touch the authenticator",
			Expected: AuthenticationExtensionsClientInputs{
				"txAuthSimple": "Touch the authenticator",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ext := UseTxAuthSimple(test.TxAuthSimple)
			aeci := AuthenticationExtensionsClientInputs{}
			ext(aeci)
			if !reflect.DeepEqual(aeci, test.Expected) {
				tt.Fatalf("Output mismatch")
			}
		})
	}
}

func TestUseTxAuthGeneric(t *testing.T) {
	type appIDTest struct {
		Name        string
		ContentType string
		Content     []byte
		Expected    AuthenticationExtensionsClientInputs
	}

	tests := []appIDTest{
		{
			Name:        "empty",
			ContentType: "",
			Content:     []byte{},
			Expected: AuthenticationExtensionsClientInputs{
				"txAuthGeneric": map[string]interface{}{
					"contentType": "",
					"content":     []byte{},
				},
			},
		},
		{
			Name:        "real",
			ContentType: "text/plain",
			Content:     []byte{1, 2, 3, 4, 5},
			Expected: AuthenticationExtensionsClientInputs{
				"txAuthGeneric": map[string]interface{}{
					"contentType": "text/plain",
					"content":     []byte{1, 2, 3, 4, 5},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			ext := UseTxAuthGeneric(test.ContentType, test.Content)
			aeci := AuthenticationExtensionsClientInputs{}
			ext(aeci)
			if !reflect.DeepEqual(aeci, test.Expected) {
				tt.Fatalf("Output mismatch got %#v expected %#v", aeci, test.Expected)
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

func TestValidateTxAuthSimple(t *testing.T) {
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
						"txAuthSimple": "Touch the authenticator",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid output type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": "Touch the authenticator",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthSimple": true,
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid input type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": 1,
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthSimple": "Touch the authenticator",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Mismatch",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": "Touch the authenticator",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthSimple": "touch the authenticator",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Good without newlines",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": "Touch the authenticator",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthSimple": "Touch the authenticator",
					},
				},
			},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": "Touch the authenticator",
				},
			},
		},
		{
			Name: "Good with newlines",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": "Touch the authenticator",
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthSimple": "Touch \nthe \nauthenticator",
					},
				},
			},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthSimple": "Touch the authenticator",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := ValidateTxAuthSimple()(test.Opts, test.Cred)
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

func TestValidateTxAuthGeneric(t *testing.T) {
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
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid output type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": true,
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Non-base64 output",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "@#@^)",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid input type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": 1,
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Input missing contentType member",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"content": []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid contentType type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": true,
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Input missing content member",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid content type",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     "",
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Invalid length",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "abcd",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
		{
			Name: "Valid SHA1",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
					},
				},
			},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
		},
		{
			Name: "Valid SHA256",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
		},
		{
			Name: "Valid SHA384",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb",
					},
				},
			},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
		},
		{
			Name: "Valid SHA512",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==",
					},
				},
			},
			ExpectedOpts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
		},
		{
			Name: "Invalid hash",
			Opts: &PublicKeyCredentialRequestOptions{
				Extensions: AuthenticationExtensionsClientInputs{
					"txAuthGeneric": map[string]interface{}{
						"contentType": "text/plain",
						"content":     []byte{},
					},
				},
			},
			Cred: &AssertionPublicKeyCredential{
				PublicKeyCredential: PublicKeyCredential{
					Extensions: AuthenticationExtensionsClientOutputs{
						"txAuthGeneric": "57DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
					},
				},
			},
			Err: ErrVerifyClientExtensionOutput,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(tt *testing.T) {
			err := ValidateTxAuthGeneric()(test.Opts, test.Cred)
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
