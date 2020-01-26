package warp

//Identifiers for defined extensions
const (
	ExtensionAppID               = "appid"
	ExtensionTxAuthSimple        = "txAuthSimple"
	ExtensionTxAuthGeneric       = "txAuthGeneric"
	ExtensionAuthnSel            = "authnSel"
	ExtensionExts                = "exts"
	ExtensionUVI                 = "uvi"
	ExtensionLoc                 = "loc"
	ExtensionUVM                 = "uvm"
	ExtensionBiometricPerfBounds = "biometricPerfBounds"
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

//RegistrationExtensionValidators is a map to all extension validators for
//extensions allowed during the registration ceremony
var RegistrationExtensionValidators map[string]RegistrationValidator = map[string]RegistrationValidator{}

//AuthenticationExtensionValidators is a map to all extension validators for
//extensions allowed during the authentication ceremony
var AuthenticationExtensionValidators map[string]AuthenticationValidator = map[string]AuthenticationValidator{
	ExtensionAppID: ValidateAppID(),
}

//ValidateAppID validates the AppID extension and updates the credential
//request options with the valid AppID as needed
func ValidateAppID() AuthenticationValidator {
	return func(opts *PublicKeyCredentialRequestOptions, cred *AssertionPublicKeyCredential) error {
		o, ok := cred.Extensions[ExtensionAppID]
		if !ok {
			return nil // do not fail on client ignored extension
		}
		i, ok := opts.Extensions[ExtensionAppID]
		if !ok {
			return ErrVerifyClientExtensionOutput.Wrap(NewError("appid extension present in credential but not requested in options"))
		}

		out, ok := o.(bool)
		if !ok {
			return ErrVerifyClientExtensionOutput.Wrap(NewError("unexpected type on appid extension output"))
		}
		in, ok := i.(string)
		if !ok {
			return ErrVerifyClientExtensionOutput.Wrap(NewError("unexpected type on appid extension input"))
		}

		if out {
			opts.RPID = in
		}
		return nil
	}
}
