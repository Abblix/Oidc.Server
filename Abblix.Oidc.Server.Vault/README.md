# Abblix.OIDC.Server.Vault

**Abblix.OIDC.Server.Vault** integrates the [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server) with the HashiCorp Vault / OpenBao **Transit** secrets engine. The provider's signing and encryption keys live inside Transit as non-exportable keys, so their private halves never enter your process. Signing and Content Encryption Key unwrapping run as Transit round-trips, addressed by each key's `kid` (its Transit key name); the public halves are fetched once at startup, published at the `/jwks` endpoint, and used for local signature verification on the hot path.

The package plugs into the OIDC server's external-key seam: a single `AddVaultExternalKeys` call registers the Transit client as the external key custodian, routes every private operation through the crypto seam, and replaces the default key provider.

## Installation

```bash
dotnet add package Abblix.OIDC.Server.Vault
```

## Usage

Register it **after** the OIDC services, so its key provider wins the singular registration. Name the Transit keys and, optionally, choose the algorithms:

```csharp
using Abblix.Jwt;

services.AddVaultExternalKeys(options =>
{
    options.Address = builder.Configuration["Vault:Address"] ?? "http://127.0.0.1:8200";
    options.Token = builder.Configuration["Vault:Token"]; // sourced from the environment, never hardcoded
    options.TransitMount = "transit";

    options.SigningKeyName = "oidc-sign";     // the Transit key name and the published signing kid
    options.EncryptionKeyName = "oidc-enc";   // the Transit key name and the published encryption kid

    // Optional: both default to the values below.
    options.SigningAlgorithm = SigningAlgorithms.RS256;
    options.EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256;
});
```

That is all: the signing key routes its signing to Transit, the encryption key routes its unwrap, and both keys' public halves appear at `/jwks`.

### Authentication

The `Token` is presented as the `X-Vault-Token` header. Source it from the environment or a secret store, never hardcode it: dev mode uses a well-known root token, while production authenticates through AppRole or Kubernetes and mints a short-lived token.

## Supported algorithms

The store maps each configured algorithm to Transit's native operation and rejects the rest, so the set below is exactly what this backend provisions.

| Operation | Algorithms | Transit key |
|---|---|---|
| Signing | RS256, RS384, RS512, PS256, PS384, PS512 | RSA |
| Signing | ES256, ES384, ES512 (raw R/S signature via Transit `jws` marshaling) | ECDSA |
| Key unwrap | RSA-OAEP-256 | RSA |

ECDH-ES key agreement is not supported: Vault Transit exposes no key-agreement primitive. For that you need a custodian built on a backend that does (for example AWS KMS `DeriveSharedSecret` or a PKCS#11 HSM), plugged into the same `IKeyCustodian` seam.

## Related Packages

| Package | Description |
|---------|-------------|
| **[Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server)** | Core OpenID Connect server implementation |
| **[Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT)** | JWT signing, encryption, and validation using .NET crypto primitives |

## Getting Started

To learn more about the Abblix OIDC Server product, visit our [Documentation](https://docs.abblix.com/docs) site and explore the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide).

## License

See [LICENSE.md](https://github.com/Abblix/Oidc.Server/blob/master/LICENSE.md).

## Contacts

- **Email**: [support@abblix.com](mailto:support@abblix.com)
- **Website**: [Abblix OIDC Server](https://www.abblix.com/abblix-oidc-server)
