// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Publishes the public halves of an <see cref="IKeyCustodian"/>'s signing and encryption keys to the OIDC
/// pipeline, one entry per current key version. It never returns private material: each key is public-only, which
/// is the signal the crypto seam reads to route the private operation to the custodian by <c>kid</c>.
/// Version-awareness rides the produce/publish split of <see cref="IAuthServiceKeysProvider"/>: every version is
/// published (so a client can verify a signature or encrypt a JWE to any of them, and a rotation overlaps), while
/// the ACTIVE version - the newest one past the server's <see cref="OidcOptions.KeyRolloverPropagation"/> window -
/// leads the set, so the produce role signs and encrypts with it. A freshly rotated version stays announced
/// (published, trailing) until it clears the window, so a client that has not refreshed its JWKS cache never sees
/// a token produced with a version it lacks. One provider serves any custodian, so the Vault and Azure packages
/// carry no key provider of their own.
/// </summary>
public sealed class ExternalKeysProvider(
    IKeyCustodian custodian,
    CustodianHeldKeys keys,
    IOptions<OidcOptions> options,
    TimeProvider timeProvider)
    : IAuthServiceKeysProvider
{
    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetSigningKeys(bool includePrivateKeys = false)
        => PublishAsync(keys.SigningKeyName, PublicKeyUsages.Signature, keys.SigningAlgorithm);

    /// <inheritdoc />
    public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(bool includePrivateKeys = false)
        // A provider that issues no encrypted token names no encryption key, and then there is nothing to publish.
        // Asking the custodian for a guessed name instead would fail against a custodian that holds only a signing
        // key, which is the common high-assurance setup.
        => keys.EncryptionKeyName is { } encryptionKeyName
            ? PublishAsync(encryptionKeyName, PublicKeyUsages.Encryption, keys.EncryptionAlgorithm)
            : AsyncEnumerable.Empty<JsonWebKey>();

    // Note: this lists the custodian's key versions on every call. Versions change on human timescales (a
    // rotation), so a production deployment caches the enumeration for a short lifetime and recomputes only the
    // produce-first ordering (cheap and time-dependent) per call. It is left uncached here to keep the seam
    // obvious; a host layers its own caching over this provider.
    private async IAsyncEnumerable<JsonWebKey> PublishAsync(
        string keyName,
        string usage,
        string algorithm,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var versions = await custodian.GetKeyVersionsAsync(keyName, cancellationToken).ToListAsync(cancellationToken);

        // Stamp the use and the configured algorithm on each version's bare public key (RSA or EC); keep the
        // version-specific kid the custodian set, falling back to the configured key name for a single-version
        // custodian that leaves the kid unset. record `with` keeps the runtime key type, so this is correct for
        // both RsaJsonWebKey and EllipticCurveJsonWebKey.
        var published = versions
            .ProduceFirst(version => version.CreatedAt, timeProvider.GetUtcNow(), options.Value.KeyRolloverPropagation)
            .Select(version => version.PublicKey with
            {
                Usage = usage,
                KeyId = version.PublicKey.KeyId ?? keyName,
                Algorithm = algorithm,
            });

        foreach (var key in published)
            yield return key;
    }
}
