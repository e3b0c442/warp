# warp - **W**eb**A**uthn **R**elying **P**arty
_warp_ is a WebAuthn Relying Party implementation which is intended to be 100% compliant with the [W3C WebAuthn Level 1](https://https://www.w3.org/TR/webauthn-1/) standard while being HTTP implementation agnostic.

## Design goals
_warp_ was built with the following goals in mind:
* 100% compliance with the WebAuthn Level 1 specification
* HTTP implementation agnostic. This library makes no assumptions about the structure or operation of your web application. Use your implementation's canonical method to parse the WebAuthn JSON.
* No assumptions about application data models. Simply implement the two required interfaces anywhere that it makes sense in your application.
* Minimal dependencies outside of the standard library, with those used chosen carefully to keep the dependency tree clean. At the time of this writing, the following external dependencies are used:
  * [fxamacker/cbor](https://github.com/fxamacker/cbor) - A fantastic CBOR implementation by Faye Amacker
* Simple package structure - just one package to import
* Structure and member naming parity with the WebAuthn spec, so that you can follow along and understand

## High level API
WebAuthn relying parties have two responsibilities: managing the _registration ceremony_, and managing the _authentication ceremony_.

### Registration:
![Registration flow](https://www.w3.org/TR/webauthn-1/images/webauthn-registration-flow-01.svg)

#### `StartRegistration`
```go
func StartRegistration(rp RelyingParty, user User, opts ...CreationOption) (*PublicKeyCredentialCreationOptions, error)
```

`StartRegistration` begins the registration ceremony by generating a cryptographic challenge and sending it to the client along with information about the user and Relying Party in the form of a [`PublicKeyCredentialCreationOptions`](https://www.w3.org/TR/webauthn-1/#dictionary-makecredentialoptions) object. 

The returned object or its data must be stored in the server-side session cache such that it can be reconstructed to pass to the
`FinishRegistration` function.

##### Parameters:
* `rp`: any value which implements the `RelyingParty` interface:
  * `RelyingPartyID()`: returns the [Relying Party ID](https://www.w3.org/TR/webauthn-1/#rp-id), which must be equal to the origin's effective domain, or a registrable domain suffix of the origin's effective domain
  * `RelyingPartyName()`: A human-palatable name for the application
  * `RelyingPartyIcon()`: A URL which resolves to an image associated with the application. This function may return the empty string.
  * `RelyingPartyOrigin()`: The fully qualified origin of the application, consisting of [scheme]://[host][:port], with port being optional if the default port for the scheme is being used.
* `user`: any value which implements the `User` interface:
  * `UserName()`: generally the username of your user; you may allow the user to choose this.
  * `UserIcon()`: A URL which resolves to an image associated with the user. This function may return the empty string.
  * `UserID()`: The user handle for the user, which is a sequence of up to 64 bytes. The ID should not contain personally identifying information about the user. It may be an internal ID (such as a database ID).
  * `UserDisplayName()`: A name for the user account intended for display.
* `opts`: zero or more `CreationOption` functions to adjust the PublicKeyCredentialCreationOptions as needed. These do not need to be set, and likely shouldn't unless you know what you are doing. The following function generators are included:
  * `Timeout(uint)`: Sets the client timeout
  * `ExcludeCredentials([]PublicKeyCredentialDescriptors)`: Provides a list of credentials to exclude
  * `AuthenticatorSelection(AuthenticatorSelectionCriteria)`: Sets the criteria for choosing an authenticator
  * `Attestation(AttestationConveyancePreference)`: Sets the preferred attestation conveyance
  * `CreationExtensions(...Extension)` takes a slice of `Extension` which can be used to set WebAuthn client extension inputs

##### Return values:
* A pointer to a `PublicKeyCredentialCreationOptions` struct. This value must be marshaled to JSON and returned to the client. It must also be stored in a server-side session cache in order to verify the client's subsequent response. Returns `nil` on error.
* An error if there was a problem generating the options struct, or `nil` on success.

#### `FinishRegistration`
```go
func FinishRegistration(rp RelyingParty, opts *PublicKeyCredentialCreationOptions, cred *AttestationPublicKeyCredential) (*WebAuthnCredential, error)
```

`FinishRegistration` completes the registration process, by verifying the public key credential sent by the client against the stored creation options. If the verification is successful, a WebAuthnCredential struct is returned with the data that must be stored for the credential.

##### Parameters:
* `rp`: As in `StartRegistration`
* `opts`: A pointer to the stored PublicKeyCredentialCreationOptions which was previously sent to the client
* `cred`: The parsed `AttestationPublicKeyCredential` that was sent from the client in response to the server challenge

##### Return values:
* A credential struct which contains the information that must be stored in order for the user to subsequently authenticate using the created credential, or `nil` on error.
* An error if there was an error verifying the returned credential, or `nil` on success.

### Authentication
![Authentication flow](https://www.w3.org/TR/webauthn-1/images/webauthn-authentication-flow-01.svg)