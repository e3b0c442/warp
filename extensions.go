package warp

//Identifiers for defined extensions
const (
	AppIDIdentifier = "appid"
)

//AuthenticationExtensionsClientInputs contains the client extension input
//values for zero or more extensions. §5.7
type AuthenticationExtensionsClientInputs map[string]interface{}

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

//AppID adds the appid extension to the extensions object. §10.1
func AppID(appID string) Extension {
	return func(e map[string]interface{}) {
		e[AppIDIdentifier] = appID
	}
}
