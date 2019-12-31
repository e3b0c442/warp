package warp

//Identifiers for defined extensions
const (
	ExtensionAppID = "appid"
)

//AuthenticationExtensionsClientInputs contains the client extension input
//values for zero or more extensions. §5.7
type AuthenticationExtensionsClientInputs map[string]interface{}

//AuthenticationExtensionsClientOutputs containing the client extension output
//values for zero or more WebAuthn extensions. §5.8
type AuthenticationExtensionsClientOutputs map[string]interface{}

//Extension defines an extension to a creation options or request options
//object
type Extension func(map[string]interface{})

//Extensions builds the extension map to be added to the options object
func Extensions(exts ...Extension) AuthenticationExtensionsClientInputs {
	extensions := make(map[string]interface{})

	for _, ext := range exts {
		ext(extensions)
	}

	return extensions
}

//UseAppID adds the appid extension to the extensions object. §10.1
func UseAppID(appID string) Extension {
	return func(e map[string]interface{}) {
		e[ExtensionAppID] = appID
	}
}

//ExtensionValidator defines a function which validates an extension output
type ExtensionValidator func(interface{}, interface{}) error

//ExtensionValidators is a map to all implemented extension validators
var ExtensionValidators map[string]ExtensionValidator = map[string]ExtensionValidator{
	ExtensionAppID: VerifyAppID,
}

//VerifyAppID verifies the AppID extension response
func VerifyAppID(_, out interface{}) error {
	if _, ok := out.(bool); ok {
		return nil
	}
	return &ErrClientExtensionVerification{Detail: "Invalid AppID output value"}
}

//EffectiveRPID returns the effective relying party ID for the ceremony based on
//the usage of the AppID extension
func EffectiveRPID(opts *PublicKeyCredentialCreationOptions, cred *AttestationPublicKeyCredential) string {
	if credV, ok := cred.Extensions[ExtensionAppID]; ok {
		if useAppID, ok := credV.(bool); ok && useAppID {
			if optsV, ok := opts.Extensions[ExtensionAppID]; ok {
				if appID, ok := optsV.(string); ok {
					return appID
				}
			}
		}
	}
	return opts.RP.ID
}
