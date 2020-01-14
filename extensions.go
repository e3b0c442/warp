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
type Extension func(AuthenticationExtensionsClientInputs)

//BuildExtensions builds the extension map to be added to the options object
func BuildExtensions(exts ...Extension) AuthenticationExtensionsClientInputs {
	extensions := make(AuthenticationExtensionsClientInputs)

	for _, ext := range exts {
		ext(extensions)
	}

	return extensions
}

//UseAppID adds the appid extension to the extensions object. §10.1
func UseAppID(appID string) Extension {
	return func(e AuthenticationExtensionsClientInputs) {
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
	return ErrVerifyClientExtensionOutput.Wrap(NewError("AppID output value must be bool"))
}

//EffectiveRPID returns the effective relying party ID for the ceremony based on
//the usage of the AppID extension
func EffectiveRPID(rp RelyingParty, in AuthenticationExtensionsClientInputs, out AuthenticationExtensionsClientOutputs) string {
	if outV, ok := out[ExtensionAppID]; ok {
		if useAppID, ok := outV.(bool); ok && useAppID {
			if inV, ok := in[ExtensionAppID]; ok {
				if appID, ok := inV.(string); ok {
					return appID
				}
			}
		}
	}

	return rp.ID()
}
