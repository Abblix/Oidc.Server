# Abblix.Jwt.Azure

**Abblix.Jwt.Azure** lets the [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server) sign and decrypt with keys protected by Azure Key Vault, in either of two postures. Hold the keys in the vault, so their private halves never enter your process and every signature is a Key Vault round-trip; or mint them in-process and seal each to a vault key, so signing stays local and only the sealed copies leave the process. Either way the public halves are published at `/jwks` and verified locally, which never calls the vault. The Azure SDK is driven through the host's `IHttpClientFactory` pipeline, so it inherits your HTTP handlers, logging and connection policy. No provider private key crosses that pipeline; what does is the signing input, the wrapped keys, and the plaintext key an unwrap returns, which a handler on this pipeline can observe, so scope logging accordingly.

Read [EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) first. It is the shared model for every custodian package: what the guarantee does and does not cover, what it costs, how rotation works, and why the placement call is required. This README covers only what is specific to Azure Key Vault.

## Installation

```bash
dotnet add package Abblix.JWT.Azure
```

## Provisioning

What you create depends on where you keep the keys ([EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) explains the choice).

Protection level is a property of the key you create, not of this package. A Standard-tier key is software-protected; Premium and Managed HSM keys (`--kty RSA-HSM`) are HSM-protected and FIPS-validated. Choose HSM-backed keys when your compliance profile requires HSM custody, or when the at-rest guarantee must hold against the vault's own operators and not only against your process.

### Keys held in the vault (`UseKeysInCustodian`)

Create the signing key, and an encryption key if you issue encrypted tokens:

```bash
az keyvault key create --vault-name my-vault --name oidc-sign --kty RSA --size 2048
az keyvault key create --vault-name my-vault --name oidc-enc  --kty RSA --size 2048  # encrypted tokens only
```

Grant the provider's identity the Key Vault Crypto User role, which covers the four operations it makes: list a key's versions, read a version's public half, sign, and unwrap. It needs no create, import, delete or purge rights. The private half never enters your process.

### Keys minted in-process (`UseKeysInProcess`)

Create one key-encryption key. The ring's container is created on first use, so you provision only its RBAC scope below, not the container itself. The server mints the signing keys and seals each to the key-encryption key, so you create no signing key by hand:

```bash
az keyvault key create --vault-name my-vault --name oidc-kek --kty RSA --size 2048
```

Grant the provider's identity two roles: Key Vault Crypto User on the key-encryption key, which now needs only read and unwrap, and Storage Blob Data Contributor on the ring's container, which lets it create, read and delete the sealed keys. Both scope to the one key and the one container, not the whole vault or account.

When two pods reach a new period together, both attempt a conditional create (`If-None-Match: *`) on the ring blob; the loser gets a 409 and reads the winner's sealed key, so neither clobbers the other and no leader is needed.

## Usage

Point the custodian at the vault, then name the Key Vault keys to produce with. Chain both calls after the OIDC registration:

```csharp
using Abblix.Jwt;
using Abblix.Jwt.Azure;
using Abblix.Oidc.Server.Features.ExternalKeys;

builder.Services
    .AddAzureCustodian(azure =>
    {
        azure.KeyVaultUri = new Uri(builder.Configuration["Azure:KeyVaultUri"]!);

        // Blank = the default Azure credential chain; see Authentication below.
        azure.TenantId = builder.Configuration["Azure:TenantId"] ?? "";
        azure.ClientId = builder.Configuration["Azure:ClientId"] ?? "";
        azure.ClientSecret = builder.Configuration["Azure:ClientSecret"] ?? ""; // never hardcoded
    })
    .UseKeysInCustodian(new CustodianHeldKeys
    {
        // The Key Vault key names. Each version publishes under its own kid, "oidc-sign/<version>".
        SigningKeyName = "oidc-sign",
        EncryptionKeyName = "oidc-enc",   // omit it if nothing encrypts to this provider: none is published

        // Optional: both default to the values below.
        SigningAlgorithm = SigningAlgorithms.RS256,
        EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
    });
```

To mint the keys in-process and keep them sealed in Blob Storage instead, name the key-encryption key and the ring's container:

```csharp
builder.Services
    .AddAzureCustodian(azure => { /* the same vault and credentials as above */ })
    .UseKeysInProcess(new MintedKeys
    {
        // The Key Vault key that seals every minted key. Asymmetric, so the seal is local.
        KeyEncryptionKeyName = "oidc-kek",

        EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256, // omit unless you issue encrypted tokens
        RotateEvery = TimeSpan.FromDays(30),                                 // optional: this is the default
    })
    .PersistRingToAzureBlob(blob =>
    {
        blob.ServiceUri = new Uri("https://myaccount.blob.core.windows.net");
        blob.Container = "oidc-keyring";   // optional: this is the default
    });
```

### Authentication

When the tenant, client and secret are all set, the custodian authenticates with a client-secret credential. Leave all three blank to fall back to `DefaultAzureCredential`, which covers a managed identity in production, an Azure CLI sign-in during development, or the `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` environment variables.

Blank is an opt-in, and it looks identical to a typo: a misspelled configuration key leaves the field empty and silently selects the credential chain instead of the service principal you meant. Prefer a managed identity and leave all three unset, or bind them from a source that fails when a key is missing. Source the secret from the environment or a secret store, never hardcode it; this package reads it at startup and neither logs nor persists it.

## Rotation

With `UseKeysInCustodian`, rotate in Key Vault, either on a rotation policy or on demand:

```bash
az keyvault key rotate --vault-name my-vault --name oidc-sign
```

Every enabled version is published under its own `kid`, `oidc-sign/<version>`. Disabling a version removes it from publication and from production immediately, so it is the fastest way to retire one; do that only after every token signed by it has expired.

With `UseKeysInProcess`, the server rotates on the `RotateEvery` schedule with no `az keyvault` call: it mints the next key, seals it into the container, and retires the old one on its own. [EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) explains the propagation window that decides when a fresh key starts signing, for both placements.

## What it costs on Key Vault

With `UseKeysInCustodian`, every issued token costs two Key Vault round-trips plus one per enabled key version: the provider lists the signing key's versions, reads each version's public half, then signs. Decrypting an inbound encrypted request object or client assertion adds an unwrap; issuing an encrypted token adds nothing, because it is wrapped to the recipient's public key locally. Nothing here is cached, so the per-version read multiplies with every version you keep enabled. Set an explicit timeout on the Key Vault calls: the Azure SDK's default retry-and-timeout policy can hold a token request open longer than your token endpoint's budget, and a hung custodian should fail fast, not stall issuance.

With `UseKeysInProcess`, token issuance makes no Key Vault call: the server signs locally and reaches the vault only to open a sealed key when a pod loads or refreshes its ring, and, for the winning key of each new period, on any pod that did not mint it. Minting needs the vault only for the key-encryption key's public half, which the server caches.

Key Vault also throttles per vault and bills per transaction. Signing counts against the vault's per-10-second limit, which drops sharply for RSA-3072 and RSA-4096; over the limit Key Vault returns HTTP 429. Check your peak token rate against the [service limits](https://learn.microsoft.com/azure/key-vault/general/service-limits) and prefer RSA-2048 or an EC key for headroom. The full picture is in [EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md).

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
| **[Abblix.JWT.Vault](https://www.nuget.org/packages/Abblix.JWT.Vault)** | HashiCorp Vault / OpenBao Transit custodian for the same external-key seam |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
