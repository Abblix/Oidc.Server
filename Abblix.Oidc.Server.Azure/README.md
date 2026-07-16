# Abblix.OIDC.Server.Azure

**Abblix.OIDC.Server.Azure** integrates the [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server) with **Azure Key Vault**. The provider's signing and encryption keys live in the vault (software- or HSM-protected), so their private halves never enter your process. Signing and Content Encryption Key unwrapping run inside the vault, addressed by each key's `kid` (its Key Vault key name); the public halves are fetched once at startup, published at the `/jwks` endpoint, and used for local signature verification on the hot path. The Azure SDK is driven through the host's `IHttpClientFactory` pipeline, so it inherits your HTTP handlers, logging and connection policy.

The package plugs into the OIDC server's external-key seam: a single `AddAzureExternalKeys` call registers the vault client as the external key store, routes every private operation through the crypto seam, and replaces the default key provider.

## Installation

```bash
dotnet add package Abblix.OIDC.Server.Azure
```

## Usage

Register it **after** the OIDC services, so its key provider wins the singular registration. Name the Key Vault keys and, optionally, choose the algorithms:

```csharp
using Abblix.Jwt;

services.AddAzureExternalKeys(options =>
{
    options.KeyVaultUri = builder.Configuration["Azure:KeyVaultUri"]!;

    options.SigningKeyName = "oidc-sign";     // the Key Vault key name and the published signing kid
    options.EncryptionKeyName = "oidc-enc";   // the Key Vault key name and the published encryption kid

    // Optional: both default to the values below.
    options.SigningAlgorithm = SigningAlgorithms.RS256;
    options.EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;

    // Leave the service-principal fields blank to use the default Azure credential chain
    // (managed identity, Azure CLI, or AZURE_* environment variables).
    options.TenantId = builder.Configuration["Azure:TenantId"] ?? "";
    options.ClientId = builder.Configuration["Azure:ClientId"] ?? "";
    options.ClientSecret = builder.Configuration["Azure:ClientSecret"] ?? ""; // from the environment, never hardcoded
});
```

That is all: the signing key routes its signing to Key Vault, the encryption key routes its unwrap, and both keys' public halves appear at `/jwks`.

### Authentication

When the tenant, client and secret are all set, the store authenticates with a client-secret credential; leave them blank to fall back to `DefaultAzureCredential`, which covers a managed identity in production, an Azure CLI sign-in during development, or the `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` environment variables. Source the secret from the environment or a secret store, never hardcode it.

## Supported algorithms

The store maps each configured algorithm to Key Vault's native operation and rejects the rest, so the set below is exactly what this backend provisions.

| Operation | Algorithms | Key Vault key |
|---|---|---|
| Signing | RS256, RS384, RS512, PS256, PS384, PS512 | RSA |
| Signing | ES256, ES384, ES512 (Key Vault returns raw R/S signatures) | EC |
| Key unwrap | RSA-OAEP-256, RSA-OAEP, RSA1_5 | RSA |

ECDH-ES key agreement is not supported: Azure Key Vault exposes no key-agreement primitive. For that you need a store built on a backend that does (for example AWS KMS `DeriveSharedSecret` or a PKCS#11 HSM), plugged into the same `IExternalKeyStore` seam.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.OIDC.Server.Vault](https://www.nuget.org/packages/Abblix.OIDC.Server.Vault)** | HashiCorp Vault / OpenBao Transit external-key integration |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
