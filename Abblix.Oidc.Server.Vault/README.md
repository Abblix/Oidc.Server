# Abblix.OIDC.Server.Vault

HashiCorp Vault / OpenBao Transit external-key integration for [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

The provider's signing and encryption keys live inside the Vault Transit secrets engine as non-exportable keys. Their private halves never enter your process: signing and CEK unwrapping happen as Transit round-trips, addressed by the key's `kid` (the Transit key name). The public halves are fetched from Transit and published to the `/jwks` endpoint and local signature verification.

## Usage

Register it after the OIDC services, naming the Transit keys:

```csharp
services.AddVaultExternalKeys(options =>
{
    options.Address = builder.Configuration["Vault:Address"] ?? "http://127.0.0.1:8200";
    options.Token = builder.Configuration["Vault:Token"]; // sourced from the environment, never hardcoded
    options.TransitMount = "transit";
    options.SigningKeyName = "oidc-sign";    // also the published signing key's kid
    options.EncryptionKeyName = "oidc-enc";  // also the published encryption key's kid
});
```

That is all: the signing key routes its signing to Vault, the encryption key routes its RSA-OAEP-256 unwrap, and both keys' public halves appear at `/jwks`. Call it after the OIDC registration, so its key provider replaces the default.

This custodian serves RSA keys (RS256 signing, RSA-OAEP-256 unwrapping), matching Transit's RSA support.

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
