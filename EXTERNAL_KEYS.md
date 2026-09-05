# External key custodians

How signing and encryption keys that live outside the process - in an HSM, a cloud KMS, or a vault - are used. This document is the shared model. It applies to every custodian package:

| Package | Custodian |
|---------|-----------|
| **[Abblix.JWT.Vault](https://www.nuget.org/packages/Abblix.JWT.Vault)** | HashiCorp Vault / OpenBao Transit |
| **[Abblix.JWT.Azure](https://www.nuget.org/packages/Abblix.JWT.Azure)** | Azure Key Vault |

Each package's README covers what is specific to its backend: how to provision the keys, how to authenticate, which algorithms it maps, and what the published `kid` looks like. Everything below is the same whichever one you pick.

## The model

A custodian is whatever holds your keys, or the key that seals them, and uses them on your behalf. With `UseKeysInCustodian` it never hands the private half over; with `UseKeysInProcess` it hands back only a key the library first sealed to it. The library talks to it through one seam, `IKeyCustodian`, with three private operations (sign, unwrap a Content Encryption Key, agree an ECDH-ES shared secret) plus an enumeration of a key's versions. The public halves come back over that same seam, and an OpenID Provider publishes them at `/jwks`.

Wiring is two steps for `UseKeysInCustodian`, three for `UseKeysInProcess` (the third names where the sealed ring lives). They are separate on purpose:

```csharp
builder.Services
    .AddVaultCustodian(vault => { /* which custodian, and how to reach it */ })
    .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
```

The first step says *which* custodian holds the keys. The second says *how* the library uses it, and that is the security posture, so you name it at the call site.

The second step is required. A custodian registered without it fails at startup, before the HTTP port opens. That failure exists because the alternative is silent and worse: the OIDC server's default key provider reads static keys from `OidcOptions`, so a half-wired custodian would otherwise serve local keys with a clean log and no complaint. Order matters in one direction only: chain these calls after `AddJsonWebTokens`, because the placement call composes the external crypto backends with their in-process peers, and those peers must already be registered. `AddOidcServices` and `AddOidcCore` perform `AddJsonWebTokens`, so for an OpenID Provider that means after the OIDC registration.

## You do not need the OIDC server for this

The *placement* step lives in [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT), and so does `AddCustodian<T>` for a custodian of your own; the two backend packages above add only the transport for their vault. Nothing in any of it mentions a client, an endpoint or a discovery document, and nothing in it needs one: a host that signs JSON Web Tokens without being an OpenID Provider - a transmitter signing Security Event Tokens, a service protecting its own state - wires a custodian without the OIDC server anywhere in its graph.

What such a host does not get is the key *provider* an OpenID Provider has, which decides what `/jwks` publishes and what each token is signed with. It reads the placement itself instead:

```csharp
// Which keys the placement named, and the custodian that holds them, are both resolvable.
var keys = provider.GetRequiredService<CustodianHeldKeys>();
var custodian = provider.GetRequiredService<IKeyCustodian>();

var versions = await custodian.GetKeyVersionsAsync(keys.SigningKeyName, cancellationToken).ToListAsync(cancellationToken);
var signingKey = versions
    .ProduceFirst(version => version.CreatedAt, timeProvider.GetUtcNow(), rolloverPropagation)
    .Select(version => version.PublicKey with
    {
        Algorithm = keys.SigningAlgorithm,

        // Falling back to the key NAME matters for a custodian that does not version its keys and leaves the kid
        // unset: signing refuses a key with no kid, because the kid is the custodian's handle for it.
        KeyId = version.PublicKey.KeyId ?? keys.SigningKeyName,
    })
    .First();
```

The key that comes back is public-only, which is the whole signal: the signing seam reads `HasPrivateKey`, finds nothing, and routes the signature to the custodian by `kid`.

The rest of this document is written from an OpenID Provider's side, because that is the host with the most moving parts. Read `/jwks` as "wherever you publish your public keys", `OidcOptions` as "your own settings", and the key provider as "whatever you wrote in place of the block above". Everything about the custodian, the placements, provisioning and rotation applies unchanged.

`rolloverPropagation` is yours to choose here - `OidcOptions.KeyRolloverPropagation`, which the [Rotation](#rotation) section names, belongs to the OIDC server this host does not have. Pick your slowest consumer's key-cache lifetime, and use the same value everywhere the key set is published, or publication and signing drift apart. `ProduceFirst` is the same arithmetic the OIDC server's provider runs, so with that one value chosen the schedule below applies unchanged.

## The two placements

The security posture is a choice, and it has two settings. They differ in one thing: whether the private half ever exists in your process.

`UseKeysInCustodian` keeps it outside. The custodian generates and holds the keys, and every signature and every Content Encryption Key unwrap is a round-trip to it. A compromised process has no key to leak, because there is none in it.

`UseKeysInProcess` brings it inside. The server generates each key, seals it to a key-encryption key the custodian holds, and keeps the sealed copies in a store you provide. Sealing is local, on that key's public half; opening a sealed key is one unwrap round-trip to the custodian, after which signing runs locally. So this is the weaker posture against a process compromise, which can reach every key the pod has opened, and the stronger one against a stolen store, which holds only ciphertext.

```csharp
builder.Services
    .AddVaultCustodian(vault => { /* which custodian, and how to reach it */ })
    .UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })
    .PersistRingToVaultKeyValue(kv => { /* where the sealed keys live */ });
```

Pick `UseKeysInCustodian` when the private half must never touch the process, and you can pay a round-trip per token for it. Pick `UseKeysInProcess` when you want signing to stay local, at the cost of holding the opened keys in memory, and you have somewhere durable to keep the sealed copies. The rest of this document notes where the two diverge.

## What the guarantee covers

With `UseKeysInCustodian`, the private half never lands in your process, so a compromised process leaks no key: nothing to exfiltrate, and nothing that outlives the credential. The custodian sees every use and, once you turn its logging on, records it.

It is not a claim that a compromised process is harmless. The process still holds the credential that reaches the custodian, and can therefore ask the custodian to sign anything for as long as that credential is valid. It also holds each unwrapped Content Encryption Key and every token it produces. So scope the credential to the operations the provider actually makes, keep its lifetime short, and alert on the custodian's log: that log, not the process, is the record of what was signed.

With `UseKeysInProcess`, the guarantee moves from the process to the store. At rest, every key is sealed to the custodian's key-encryption key, so the store, its backups and its snapshots hold only ciphertext, and losing the store alone loses nothing usable. In memory is another matter: a pod opens every key in its ring to serve them, and the credential it holds will unwrap any entry the custodian decrypts. So a process compromise exposes the whole ring, not just the key in use, and the store's ciphertext stops protecting you once that credential is taken too. Treat a process compromise as a key-exposure event: rotate the signing keys and revoke the credential. Signing is also local here, so the custodian sees only unwraps, never a signature: the external, tamper-evident record of what was signed that `UseKeysInCustodian` gives you does not exist in this placement. If you need that record, keep the custodian-held placement, or emit and independently protect your own signing log.

## Cost of the guarantee

`UseKeysInCustodian` puts a network call on the path of every token, because the private half stays outside:

- Every issued token costs at least two round-trips: at least one to discover the signing key's versions (some backends read each version separately), and one to sign. Decrypting inbound encrypted material, an encrypted request object or client assertion, adds an unwrap; issuing an encrypted token adds nothing, because it is wrapped to the recipient's public key locally. Signature verification is local and free, because it runs on the published public halves.
- The provider does not cache: it lists key versions on every call, so without a short-lived cache in front of it, every `/jwks` hit and every token issuance reaches the custodian. `/jwks` is public and unauthenticated, so an uncached provider lets any client or scraper amplify load and cost onto the custodian and trip its rate limits, which then stops token issuance too. Wrap the registered `IAuthServiceKeysProvider` in a short-lived cache in production; versions change on human timescales, so the cache does not hide a rotation.
- Availability is coupled. A custodian that is unreachable, sealed or throttling means no tokens issued and no `/jwks` served. Size it for your peak token rate and set an explicit HTTP timeout.
- The latency lands on the token endpoint, not at startup.

`UseKeysInProcess` moves that cost off the token path and onto a schedule. Signing runs locally, so a token costs no round-trip. The custodian is reached to open a sealed key: once per key when a pod loads or refreshes its ring, and once for the winning key of each new period on any pod that did not mint it. Minting itself is local, so it needs the custodian only for the key-encryption key's public half, which the server caches. A custodian outage therefore does not stop a pod signing with keys it has already opened, but a pod starting cold cannot open the ring, and once a period rotates, a pod that did not mint the new key cannot open it until the custodian returns. Plan your outage tolerance around the rotation interval, not just steady state. In exchange you run a store: durable, reachable from every pod, and the one piece of shared state the other placement does without.

Your backend's README gives the concrete numbers and the store it uses.

## Provisioning

The keys are yours, not the library's, and what you create depends on the placement.

For `UseKeysInCustodian`, create the signing key (and an encryption key if you issue encrypted tokens) in the custodian before the first run, and keep them non-exportable: a key that can be exported, or backed up in the clear, defeats the point of holding it there. Grant the provider's credential only the operations it makes: read the key to publish its public halves, sign, and decrypt. It never needs to create, import, delete or export a key.

For `UseKeysInProcess`, create one key-encryption key instead. It must be asymmetric, so the server can seal against its public half without a round-trip, and it never signs anything: it only wraps and unwraps the keys the server mints. Grant the credential read and unwrap on that one key, and the store its own read, write, list and delete, since the server enumerates the ring when a pod loads and retires old entries itself. The signing keys are not provisioned by hand; the server mints them, RS256 over RSA-2048 by default, which `SigningAlgorithm` and `RsaKeySize` on `MintedKeys` change.

Nothing in the library can detect an exportable key or an over-broad grant, so both are decisions you own. Your backend's README gives the concrete policy or role for each placement.

## Rotation

Rotation differs by placement, but both overlap old and new so a client with a stale JWKS cache never meets a key it has not seen.

With `UseKeysInCustodian` you rotate in the custodian, and nothing redeploys. Every version of a key is published at `/jwks`, each under its own `kid`. The version the provider signs with is the newest one older than `OidcOptions.KeyRolloverPropagation` (default 1 hour): a new version is published immediately but starts signing only once that window has passed. Older versions keep verifying and unwrapping until you retire them, so remove one only after every token signed by it has expired.

With `UseKeysInProcess` the server rotates on its own schedule: it mints the next key ahead of time, publishes it, and starts signing with it once the same propagation window has passed, then retires the previous one after it is no longer needed. You provision nothing per rotation. Pods do not elect a leader; the first to reach a new period wins it through the store's insert-if-absent write, and the rest read the winner's key. Rotating the key-encryption key needs no re-sealing either: each sealed entry names the version that sealed it, so a new version seals new keys while older entries keep opening under theirs.

The `/jwks` response carries a `Cache-Control` max-age derived from the propagation window, so publication and signing cannot drift apart. Set the window to your slowest client's JWKS cache lifetime. Either way, every pod derives the same active version from the version creation times and this window, so the deployment needs no coordination beyond the store `UseKeysInProcess` already relies on.

## Bringing your own custodian

The seam is public. If your keys live somewhere these packages do not cover, implement `IKeyCustodian` and wire it the same way:

```csharp
builder.Services
    .AddCustodian<MyCustodian>()
    .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
```

`AddCustodian<T>` builds your custodian through the container, so it may depend on your own services. If you registered it yourself instead - as a typed `HttpClient`, or as an instance you built - call `RequireKeyPlacement()` in its place: it registers nothing and only opens the placement choice, which is the step that must not be skipped. Either way the custodian must be a singleton, because the signing and decryption backends that reach it are; a shorter lifetime is refused at the placement call rather than left to pin one scope's custodian for the life of the process.

Implement only the operations your keys need, and the placement narrows that further: `UseKeysInProcess` calls only `UnwrapKeyAsync` and the version enumeration, because the signing runs in the process, while `UseKeysInCustodian` also needs `SignAsync`. A signing-only custodian leaves unwrap and agree unreachable. Address every private operation by the `kid` you published for that key version. Direct encryption (`dir`) and password-based key management (PBES2) have no external form, since the CEK is the secret itself or is derived from it, so they never route to a custodian and fail closed.

`AgreeKeyAsync` is the seam's answer to ECDH-ES. Neither Vault Transit nor Azure Key Vault exposes a key-agreement primitive, so their packages leave it unsupported; a backend that does offer one (AWS KMS `DeriveSharedSecret`, or a PKCS#11 HSM) can implement it against the same seam.

## Related

- [Documentation](https://docs.abblix.com/docs) and the [Getting Started Guide](https://docs.abblix.com/docs/getting-started-guide)
- [Abblix.OIDC.Server](https://www.nuget.org/packages/Abblix.OIDC.Server) - the core OpenID Connect server
- [Abblix.JWT](https://www.nuget.org/packages/Abblix.JWT) - JWT signing, encryption and validation
