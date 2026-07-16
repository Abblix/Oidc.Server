# Abblix.OIDC.Server.Azure

Azure Key Vault external-key integration for [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server).

The provider's signing and encryption keys live in Azure Key Vault (software- or HSM-protected). Their private halves never enter your process: signing and CEK unwrapping run inside the vault, addressed by the key's `kid` (the Key Vault key name). The public halves are fetched from the vault and published to the `/jwks` endpoint and local signature verification.

## Usage

Register it after the OIDC services, naming the Key Vault keys:

```csharp
services.AddAzureExternalKeys(options =>
{
    options.KeyVaultUri = builder.Configuration["Azure:KeyVaultUri"]!;
    options.SigningKeyName = "oidc-sign";    // also the published signing key's kid
    options.EncryptionKeyName = "oidc-enc";  // also the published encryption key's kid
    // Leave the service-principal fields blank to use the default Azure credential chain
    // (managed identity, Azure CLI, or AZURE_* environment variables):
    options.TenantId = builder.Configuration["Azure:TenantId"] ?? "";
    options.ClientId = builder.Configuration["Azure:ClientId"] ?? "";
    options.ClientSecret = builder.Configuration["Azure:ClientSecret"] ?? ""; // from the environment, never hardcoded
});
```

That is all: the signing key routes its signing to Key Vault, the encryption key routes its RSA-OAEP-256 unwrap, and both keys' public halves appear at `/jwks`. Call it after the OIDC registration, so its key provider replaces the default.

This custodian serves RSA keys (RS256 signing, RSA-OAEP-256 unwrapping).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).
