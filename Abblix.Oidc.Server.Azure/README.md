# Abblix.OIDC.Server.Azure

**Abblix.OIDC.Server.Azure** lets the [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server) sign and decrypt with keys held in Azure Key Vault. The keys live in the vault, so their private halves never enter your process. Signing and Content Encryption Key unwrapping run as Key Vault round-trips; the public halves are published at `/jwks` and verified locally, which never calls the vault. The Azure SDK is driven through the host's `IHttpClientFactory` pipeline, so it inherits your HTTP handlers, logging and connection policy; no key material crosses that pipeline in the clear, only digests and wrapped keys.

Read [EXTERNAL-KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL-KEYS.md) first. It is the shared model for every custodian package: what the guarantee does and does not cover, what it costs, how rotation works, and why the tier call is required. This README covers only what is specific to Azure Key Vault.

## Installation

```bash
dotnet add package Abblix.OIDC.Server.Azure
```

## Provisioning

Create the keys in the vault before the first run:

```bash
az keyvault key create --vault-name my-vault --name oidc-sign --kty RSA --size 2048
az keyvault key create --vault-name my-vault --name oidc-enc  --kty RSA --size 2048  # encrypted tokens only
```

Protection level is a property of the key you create, not of this package. A Standard-tier key is software-protected; Premium and Managed HSM keys (`--kty RSA-HSM`) are HSM-protected and FIPS-validated. Choose HSM-backed keys when the guarantee has to hold against a vault operator, not only against your own process. The private half never enters your process either way.

Grant the provider's identity the Key Vault Crypto User role, which covers the four operations it makes: list a key's versions, read a version's public half, sign, and unwrap. It needs no create, import, delete or purge rights.

## Usage

Point the custodian at the vault, then name the Key Vault keys to produce with. Chain both calls after the OIDC registration:

```csharp
using Abblix.Jwt;
using Abblix.Oidc.Server.Azure;
using Abblix.Oidc.Server.Features.ExternalKeys;

builder.Services
    .AddAzureCustodian(azure =>
    {
        azure.KeyVaultUri = builder.Configuration["Azure:KeyVaultUri"]!;

        // Blank = the default Azure credential chain; see Authentication below.
        azure.TenantId = builder.Configuration["Azure:TenantId"] ?? "";
        azure.ClientId = builder.Configuration["Azure:ClientId"] ?? "";
        azure.ClientSecret = builder.Configuration["Azure:ClientSecret"] ?? ""; // never hardcoded
    })
    .HoldKeysInCustodian(new CustodianHeldKeys
    {
        // The Key Vault key names. Each version publishes under its own kid, "oidc-sign/<version>".
        SigningKeyName = "oidc-sign",
        EncryptionKeyName = "oidc-enc",   // omit it if you issue no encrypted tokens: none is published

        // Optional: both default to the values below.
        SigningAlgorithm = SigningAlgorithms.RS256,
        EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
    });
```

### Authentication

When the tenant, client and secret are all set, the custodian authenticates with a client-secret credential. Leave all three blank to fall back to `DefaultAzureCredential`, which covers a managed identity in production, an Azure CLI sign-in during development, or the `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` environment variables.

Blank is an opt-in, and it looks identical to a typo: a misspelled configuration key leaves the field empty and silently selects the credential chain instead of the service principal you meant. Prefer a managed identity and leave all three unset, or bind them from a source that fails when a key is missing. Source the secret from the environment or a secret store, never hardcode it; this package reads it at startup and neither logs nor persists it.

## Rotation

Rotate in Key Vault, either on a rotation policy or on demand:

```bash
az keyvault key rotate --vault-name my-vault --name oidc-sign
```

Every enabled version is published under its own `kid`, `oidc-sign/<version>`. Disabling a version removes it from publication and from production immediately, so it is the fastest way to retire one; do that only after every token signed by it has expired. [EXTERNAL-KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL-KEYS.md) explains the propagation window that decides when a fresh version starts signing.

## What it costs on Key Vault

Every issued token costs two Key Vault round-trips plus one per enabled key version: the provider lists the signing key's versions, reads each version's public half, then signs. An encrypted token adds an unwrap. Nothing here is cached, so the per-version read multiplies with every version you keep enabled.

Key Vault also throttles per vault and bills per transaction. Signing counts against the vault's per-10-second limit, which drops sharply for RSA-3072 and RSA-4096; over the limit Key Vault returns HTTP 429. Check your peak token rate against the [service limits](https://learn.microsoft.com/azure/key-vault/general/service-limits) and prefer RSA-2048 or an EC key for headroom. The full picture is in [EXTERNAL-KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL-KEYS.md).

## Supported algorithms

This package maps each algorithm below to Key Vault's native operation and rejects any other, so this is the set it supports. Key Vault itself offers more; a row is added here only when the mapping and its round-trip are covered by tests.

| Operation | Algorithms | Key Vault key |
|---|---|---|
| Signing | RS256, RS384, RS512, PS256, PS384, PS512 | RSA |
| Signing | ES256, ES384, ES512 (Key Vault returns raw R/S signatures) | EC |
| Key unwrap | RSA-OAEP-256 (recommended), RSA-OAEP, RSA1_5 (legacy) | RSA |

RSA-OAEP-256 is the default and the one to use. RSA-OAEP and RSA1_5 are here for clients that cannot be moved yet: RSA1_5 in particular is PKCS#1 v1.5 key transport, which RFC 8725 discourages. That is why an unwrap failure is reported the same way as a wrong key: it keeps the padding oracle closed. Do not enable it for a new deployment. The algorithm is fixed by `EncryptionAlgorithm` at startup; it is not negotiated per request.

ECDH-ES key agreement is not supported: Azure Key Vault exposes no key-agreement primitive.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.OIDC.Server.Vault](https://www.nuget.org/packages/Abblix.OIDC.Server.Vault)** | HashiCorp Vault / OpenBao Transit custodian for the same external-key seam |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
