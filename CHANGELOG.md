# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.2.0] - 2020-01-19
### Added
- `UnmarshalBinary` and `MarshalBinary` methods on `AttestationObject` and `AuthenticatorData`, implementing the `BinaryMarshaler` and `BinaryUnmarshaler` interfaces
- `Encode` method on `AuthenticatorData` to facilitate encoding `AttestationObject` for storage

### Changed
- **[BREAKING]** `FinishRegistration` now returns `(*AttestationObject, error)` instead of `(string, []byte, error)`, to allow the implementor to choose how much or little of the authenticator data to save.
- **[BREAKING]** `FinishAuthentication` now returns `(*AuthenticatorData, error)` instead of `(uint, error)`, to allow the implementor full access to the authenticator data for other uses
- **[BREAKING]** AttestationObject now holds the parsed AuthenticatorData instead of the raw bytes
- **[BREAKING]** Rename methods on `RelyingParty`, `User`, and `Credential` interfaces to reduce the risk of conflicts with lower-order data members
- **[BREAKING]** Change `EntityID()` (formerly `ID()`) method on `Credential` interface to return `[]byte` instead of `string`
- **[BREAKING]** Change `CredFinder` function type to accept argument of type `[]byte` instead of `string`
- **[BREAKING]** `AttestedCredentialData` `CredentialPublicKey` member is now the raw `cbor.RawMessage` instead of the parsed `COSEKey`
- Changed `verifyAttestationStatement` to take the `AttestationObject` instead of its separated components.
- Updated [github.com/fxamacker/cbor](https://github.com/fxamacker/cbor) to version 1.5.0 and changed encoding options on all calls to the new convenience functions
- Updated the demo app to reflect breaking changes


## [0.1.0] - 2020-01-14
### Added
- Initial implementation
