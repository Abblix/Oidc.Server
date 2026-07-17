# External key custodians

How the Abblix OIDC Server uses signing and encryption keys that live outside the process, in an HSM, a cloud KMS, or a vault. This document is the shared model. It applies to every custodian package:

| Package | Custodian |
|---------|-----------|
| **[Abblix.OIDC.Server.Vault](https://www.nuget.org/packages/Abblix.OIDC.Server.Vault)** | HashiCorp Vault / OpenBao Transit |
| **[Abblix.OIDC.Server.Azure](https://www.nuget.org/packages/Abblix.OIDC.Server.Azure)** | Azure Key Vault |

Each package's README covers what is specific to its backend: how to provision the keys, how to authenticate, which algorithms it maps, and what the published `kid` looks like. Everything below is the same whichever one you pick.

## The model

A custodian is whatever holds your private keys and is willing to use them on your behalf without handing them over. The library talks to it through one seam, `IKeyCustodian`, with three private operations (sign, unwrap a Content Encryption Key, agree an ECDH-ES shared secret) plus an enumeration of a key's versions. The public halves come back over that same seam and are published at `/jwks`.

Wiring is two steps, and they are separate on purpose:

```csharp
builder.Services
    .AddVaultCustodian(vault => { /* which custodian, and how to reach it */ })
    .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
```

The first step says *which* custodian holds the keys. The second says *how* the library uses it, and that is the security posture, so you name it at the call site. Today there is one such call, `HoldKeysInCustodian`: the private half never enters the process, and every signature and every CEK unwrap is a round-trip to the custodian.

The second step is required. A custodian registered without it fails at startup, before the HTTP port opens. That failure exists because the alternative is silent and worse: the library's default key provider reads static keys from `OidcOptions`, so a half-wired custodian would otherwise serve local keys with a clean log and no complaint. Order matters in one direction only: chain both calls after the OIDC registration (`AddOidcServices` / `AddOidcCore`), because the tier call composes the external crypto backends with their in-process peers, and those peers must already be registered.

## What the guarantee covers

The private half never lands in your process, so a compromised process leaks no key: nothing to exfiltrate, and nothing that outlives the credential. The custodian sees every use and, once you turn its logging on, records it.

It is not a claim that a compromised process is harmless. The process still holds the credential that reaches the custodian, and can therefore ask the custodian to sign anything for as long as that credential is valid. It also holds each unwrapped Content Encryption Key and every token it produces. So scope the credential to the operations the provider actually makes, keep its lifetime short, and alert on the custodian's log: that log, not the process, is the record of what was signed.

## Cost of the guarantee

The private half stays outside, so every private operation is a network call. Budget for it before adopting:

- Every issued token costs at least two round-trips: one to list the signing key's versions, one to sign. An encrypted token adds one more. Signature verification is local and free, because it runs on the published public halves.
- The provider does not cache. It lists key versions on every call, deliberately, to keep the seam inspectable. Versions change on human timescales, so a production host wraps the registered `IAuthServiceKeysProvider` in its own short-lived cache. Without one, every `/jwks` hit and every token issuance reaches the custodian.
- Availability is coupled. A custodian that is unreachable, sealed or throttling means no tokens issued and no `/jwks` served. Size it for your peak token rate and set an explicit HTTP timeout.
- The latency lands on the token endpoint, not at startup.

Your backend's README gives the exact per-token cost, which differs: some custodians answer a version listing in one call, others charge one call per version, and some throttle or bill per operation.

## Provisioning

The keys are yours, not the library's. Create them in the custodian before the first run, and keep them non-exportable: a key that can be exported, or backed up in the clear, defeats the point of holding it there. Nothing in the library can detect that, so it is a decision you own.

Grant the provider's credential only the operations it makes: read the key (to publish its public halves), sign, and decrypt. It never needs to create, import, delete or export a key. Your backend's README gives the concrete policy or role.

## Rotation

Rotate in the custodian. Nothing redeploys, and pods do not coordinate.

Every version of a key is published at `/jwks`, each under its own `kid`, so a rotation overlaps instead of cutting over. The version the provider signs with is the newest one older than `OidcOptions.KeyRolloverPropagation` (default 1 hour): a new version is published immediately but starts signing only once that window has passed, so a client whose JWKS cache is up to an hour stale never meets a token signed by a key it has not seen. The `/jwks` response carries a `Cache-Control` max-age derived from the same window, so the two cannot drift apart. Set the window to your slowest client's JWKS cache lifetime.

Older versions keep verifying and unwrapping until you retire them, so remove one only after every token signed by it has expired.

Every pod derives the same active version from the version creation times and this window, so a multi-pod deployment needs no leader and no shared state.

## Bringing your own custodian

The seam is public. If your keys live somewhere these packages do not cover, implement `IKeyCustodian` and wire it the same way:

```csharp
builder.Services
    .AddCustodian<MyCustodian>()
    .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
```

Implement only the operations your keys need: a signing-only custodian leaves unwrap and agree unreachable. Address every private operation by the `kid` you published for that key version. Direct encryption (`dir`) and password-based key management (PBES2) have no external form, since the CEK is the secret itself or is derived from it, so they never route to a custodian and fail closed.

`AgreeKeyAsync` is the seam's answer to ECDH-ES. Neither Vault Transit nor Azure Key Vault exposes a key-agreement primitive, so their packages leave it unsupported; a backend that does offer one (AWS KMS `DeriveSharedSecret`, or a PKCS#11 HSM) can implement it against the same seam.

## Related

- [Documentation](https://docs.abblix.com/docs) and the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide)
- [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) - the core OpenID Connect server
- [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT) - JWT signing, encryption and validation
