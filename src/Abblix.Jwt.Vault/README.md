# Abblix.Jwt.Vault

**Abblix.Jwt.Vault** lets any [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT) host - the [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server) included, but equally a service that only signs tokens - sign and decrypt with keys protected by the HashiCorp Vault / OpenBao Transit secrets engine, in either of two postures. Hold the keys inside Transit, non-exportable, so their private halves never enter your process and every signature is a Transit round-trip; or mint them in-process and seal each to a Transit key, so signing stays local and only the sealed copies leave the process. Either way only public halves are published, and signature verification runs locally and never calls Transit.

Read [EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) first. It is the shared model for every custodian package: what the guarantee does and does not cover, what it costs, how rotation works, and why the placement call is required. This README covers only what is specific to Vault.

## Installation

```bash
dotnet add package Abblix.JWT.Vault
```

## Provisioning

What you create depends on where you keep the keys ([EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) explains the choice). Scope the provider's token to the paths of the placement you pick and nothing else. Never a root or admin token.

### Keys held in Transit (`UseKeysInCustodian`)

Create the signing key, and an encryption key if you issue encrypted tokens, before the first run. They stay non-exportable, which is the default:

```bash
vault secrets enable transit
vault write -f transit/keys/oidc-sign type=rsa-2048        # exportable stays false
vault write -f transit/keys/oidc-enc  type=rsa-2048        # only if you issue encrypted tokens
```

```hcl
path "transit/keys/oidc-sign"    { capabilities = ["read"] }    # publish the public halves
path "transit/sign/oidc-sign"    { capabilities = ["update"] }  # sign tokens
path "transit/keys/oidc-enc"     { capabilities = ["read"] }
path "transit/decrypt/oidc-enc"  { capabilities = ["update"] }  # unwrap a CEK
```

The token reads, signs and decrypts only. It never needs to create, import, delete or export a key.

### Keys minted in-process (`UseKeysInProcess`)

Create one key-encryption key, and a KV version 2 engine for the ring. The server mints the signing keys itself and seals each to the key-encryption key, so you provision no signing key by hand:

```bash
vault secrets enable transit
vault write -f transit/keys/oidc-kek type=rsa-2048         # asymmetric: sealed locally, unwrapped in Vault
vault secrets enable -path=secret -version=2 kv            # the ring; matches the Mount option below
```

```hcl
path "transit/keys/oidc-kek"          { capabilities = ["read"] }                      # publish the KEK public half to seal locally
path "transit/decrypt/oidc-kek"       { capabilities = ["update"] }                    # unwrap a sealed key
path "secret/data/oidc-keyring/*"     { capabilities = ["create", "update", "read"] }  # write and read ring entries
path "secret/metadata/oidc-keyring/*" { capabilities = ["delete"] }                    # retire an entry
path "secret/metadata/oidc-keyring"   { capabilities = ["list"] }                      # list the ring
```

The `update` on the data path is not spare: two pods reaching a new period both write it, and the one that loses needs `update` to receive Vault's routine "already written" answer instead of a 403.

A default Transit key is software-protected inside Vault's barrier, so the ring holding only ciphertext protects you against a stolen store but not against a Vault operator or root token. Where your Vault supports it, back the key-encryption key with an HSM seal or Managed Keys so the at-rest guarantee holds against the custodian's own operators too.

## Usage

Point the custodian at Vault, then name the Transit keys to produce with. Chain both calls after `AddJsonWebTokens`, which the OIDC registration performs for you:

```csharp
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Jwt.Vault;

builder.Services
    .AddVaultCustodian(vault =>
    {
        // Vault must be reached over TLS: this connection carries the token and every signature.
        vault.Address = builder.Configuration["Vault:Address"]
            ?? throw new InvalidOperationException("Vault:Address is not configured.");
        vault.Token = builder.Configuration["Vault:Token"]; // from the environment, never hardcoded
        vault.TransitMount = "transit";                     // optional: this is the default mount
    })
    .UseKeysInCustodian(new CustodianHeldKeys
    {
        // The Transit key names. Each version publishes under its own kid, "oidc-sign:1" and so on.
        SigningKeyName = "oidc-sign",
        EncryptionKeyName = "oidc-enc",   // omit it if nothing encrypts to this provider: none is published

        // Optional: defaults to RS256.
        SigningAlgorithm = SigningAlgorithms.RS256,

        // Transit unwraps RSA-OAEP-256 only, so this is its one valid value.
        EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
    });
```

To mint the keys in-process and keep them sealed in Vault instead, name the key-encryption key and where the ring lives:

```csharp
builder.Services
    .AddVaultCustodian(vault => { /* the same address and token as above */ })
    .UseKeysInProcess(new MintedKeys
    {
        // The Transit key that seals every minted key. Asymmetric, so the seal is local.
        KeyEncryptionKeyName = "oidc-kek",

        EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256, // omit unless you issue encrypted tokens
        RotateEvery = TimeSpan.FromDays(30),                                 // optional: this is the default
    })
    .PersistRingToVaultKeyValue(kv =>
    {
        kv.Mount = "secret";        // optional: the KV v2 mount, this is the default
        kv.Path = "oidc-keyring";   // optional: the path the ring lives under, this is the default
    });
```

### Authentication

The `Token` is presented as the `X-Vault-Token` header. Source it from the environment or a secret store, never hardcode it; this package reads it at startup and neither logs nor persists it.

Reach Vault over TLS in every environment that is not a local dev container: the header is a bearer credential, and anyone who reads it off the wire can sign tokens as your provider until it expires. Vault's own `vault server -dev` mode issues a well-known root token and listens on plaintext `http://127.0.0.1:8200`; that combination suits a throwaway dev server and nothing else. In production, authenticate through AppRole or Kubernetes auth, mint a short-lived token, and scope it with the policy for the placement you chose above.

### The HTTP pipeline

Both engines share one client from the host's `IHttpClientFactory`, so retries, a circuit breaker, timeouts, a proxy or a client certificate are added with the standard APIs and nothing of ours.

To make every outbound client of your application resilient, including this one, name none of them:

```csharp
services.ConfigureHttpClientDefaults(http => http.AddStandardResilienceHandler());
```

To configure this package's client alone - a longer retry for Vault than for anything else, say - name it:

```csharp
services.AddHttpClient(VaultTransport.HttpClientName)
    .AddStandardResilienceHandler();   // Microsoft.Extensions.Http.Resilience
```

Either call goes before or after `AddVaultCustodian`; both reach the same client. What you chain applies to every Vault call the custodian and the key ring make, and to no other client.

## Rotation

With `UseKeysInCustodian`, rotate in Transit:

```bash
vault write -f transit/keys/oidc-sign/rotate
```

Every version is published under its own `kid`, `oidc-sign:1` and so on, and each signing request pins the exact version its `kid` names, so a token is never signed by a version the client cannot resolve. Older versions keep verifying and unwrapping until you remove them from Transit.

With `UseKeysInProcess`, the server rotates on the `RotateEvery` schedule with no `vault write` at all: it mints the next key, seals it into the ring, and retires the old one on its own. [EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md) explains the propagation window that decides when a fresh key starts signing, for both placements.

## What it costs on Transit

With `UseKeysInCustodian`, every issued token costs at least two Transit round-trips: one to list the signing key's versions, one to sign. Decrypting an inbound encrypted request object or client assertion adds an unwrap; issuing an encrypted token adds nothing, because it is wrapped to the recipient's public key locally. Nothing here is cached, and Transit is a hard dependency of token issuance, so size it for your peak token rate. Set an explicit HTTP timeout: a hung call is otherwise bounded only by `HttpClient.Timeout`, which defaults to 100 seconds.

With `UseKeysInProcess`, token issuance makes no Transit call: the server signs locally and reaches Transit only to open a sealed key when a pod loads or refreshes its ring, and, for the winning key of each new period, on any pod that did not mint it. Minting needs Transit only for the key-encryption key's public half, which the server caches. The full picture is in [EXTERNAL_KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL_KEYS.md).

## Supported algorithms

This package maps each algorithm below to Transit's native operation and rejects any other, so this is the set it supports. Transit itself offers more; a row is added here only when the mapping and its round-trip are covered by tests.

| Operation | Algorithms | Transit key |
|---|---|---|
| Signing | RS256, RS384, RS512, PS256, PS384, PS512 | RSA |
| Signing | ES256, ES384, ES512 (raw R/S signature via Transit `jws` marshaling) | ECDSA |
| Key unwrap | RSA-OAEP-256 | RSA |

ECDH-ES key agreement is not supported: Vault Transit exposes no key-agreement primitive.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.JWT.Azure](https://www.nuget.org/packages/Abblix.JWT.Azure)** | Azure Key Vault custodian for the same external-key seam |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- **General inquiries**: [info@abblix.com](mailto:info@abblix.com)
- **Support and security reports**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
