# Abblix.OIDC.Server.Vault

**Abblix.OIDC.Server.Vault** lets the [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server) sign and decrypt with keys held in the HashiCorp Vault / OpenBao Transit secrets engine. The keys live inside Transit as non-exportable keys (software-protected, inside Vault's encrypted barrier), so their private halves never enter your process. Signing and Content Encryption Key unwrapping run as Transit round-trips; the public halves are published at `/jwks` and verified locally, which never calls Transit.

Read [EXTERNAL-KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL-KEYS.md) first. It is the shared model for every custodian package: what the guarantee does and does not cover, what it costs, how rotation works, and why the tier call is required. This README covers only what is specific to Vault.

## Installation

```bash
dotnet add package Abblix.OIDC.Server.Vault
```

## Provisioning

Create the keys in Transit before the first run, and leave them non-exportable, which is the default:

```bash
vault secrets enable transit
vault write -f transit/keys/oidc-sign type=rsa-2048        # exportable stays false
vault write -f transit/keys/oidc-enc  type=rsa-2048        # only if you issue encrypted tokens
```

Scope the provider's token to the paths it uses and nothing else. Never a root or admin token:

```hcl
path "transit/keys/oidc-sign"    { capabilities = ["read"] }    # publish the public halves
path "transit/sign/oidc-sign"    { capabilities = ["update"] }  # sign tokens
path "transit/keys/oidc-enc"     { capabilities = ["read"] }
path "transit/decrypt/oidc-enc"  { capabilities = ["update"] }  # unwrap a CEK
```

## Usage

Point the custodian at Vault, then name the Transit keys to produce with. Chain both calls after the OIDC registration:

```csharp
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Abblix.Oidc.Server.Vault;

builder.Services
    .AddVaultCustodian(vault =>
    {
        // Vault must be reached over TLS: this connection carries the token and every signature.
        vault.Address = builder.Configuration["Vault:Address"]
            ?? throw new InvalidOperationException("Vault:Address is not configured.");
        vault.Token = builder.Configuration["Vault:Token"]; // from the environment, never hardcoded
        vault.TransitMount = "transit";                     // optional: this is the default mount
    })
    .HoldKeysInCustodian(new CustodianHeldKeys
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

### Authentication

The `Token` is presented as the `X-Vault-Token` header. Source it from the environment or a secret store, never hardcode it; this package reads it at startup and neither logs nor persists it.

Reach Vault over TLS in every environment that is not a local dev container: the header is a bearer credential, and anyone who reads it off the wire can sign tokens as your provider until it expires. Vault's own `vault server -dev` mode issues a well-known root token and listens on plaintext `http://127.0.0.1:8200`; that combination suits a throwaway dev server and nothing else. In production, authenticate through AppRole or Kubernetes auth, mint a short-lived token, and scope it with the policy above.

## Rotation

Rotate in Transit:

```bash
vault write -f transit/keys/oidc-sign/rotate
```

Every version is published under its own `kid`, `oidc-sign:1` and so on, and each signing request pins the exact version its `kid` names, so a token is never signed by a version the client cannot resolve. Older versions keep verifying and unwrapping until you remove them from Transit. [EXTERNAL-KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL-KEYS.md) explains the propagation window that decides when a fresh version starts signing.

## What it costs on Transit

Every issued token costs at least two Transit round-trips: one to list the signing key's versions, one to sign. An encrypted token adds a third. Nothing here is cached, and Transit is a hard dependency of token issuance, so size it for your peak token rate. Set an explicit HTTP timeout: a hung call is otherwise bounded only by `HttpClient.Timeout`, which defaults to 100 seconds. The full picture is in [EXTERNAL-KEYS.md](https://github.com/Abblix/Oidc.Server/blob/master/EXTERNAL-KEYS.md).

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
| **[Abblix.OIDC.Server.Azure](https://www.nuget.org/packages/Abblix.OIDC.Server.Azure)** | Azure Key Vault custodian for the same external-key seam |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
