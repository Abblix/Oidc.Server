// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.Logging;
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
public sealed partial class ExternalKeysProvider(
    ILogger<ExternalKeysProvider> logger,
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

    // The last enumeration that succeeded, per key name. It is not an optimization: the published set is what
    // relying parties verify already-issued tokens against, so letting a custodian outage empty it stops them
    // validating tokens that are perfectly good, which is a wider outage than the one that caused it. Serving
    // the previous set costs freshness, and OpenID Connect Core 10.1.1 asks the document to keep recently
    // retired keys for a while anyway.
    //
    // Only a TEMPORARY failure is served from here, and the distinction is not bookkeeping. A permanent one is
    // an operator disabling a key or revoking this identity's read on it, so falling back would keep publishing
    // a key that was deliberately retired, keep offering it to sign with, and keep advertising an encryption
    // key nothing can unwrap with - for the life of the process, since only a later success replaces the entry.
    //
    // The staleness runs both ways, and this instance cannot tell which it is in: the failure caught here is
    // ITS failure, not the custodian's, so another instance may have rotated meanwhile and this set would miss
    // the new version. KeyRingRefreshService says the same of the minted-key path. That is why the fallback is
    // reported rather than silent.
    private readonly ConcurrentDictionary<string, IReadOnlyList<KeyVersion>> _lastPublished = new();

    private async IAsyncEnumerable<JsonWebKey> PublishAsync(
        string keyName,
        string usage,
        string algorithm,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        IReadOnlyList<KeyVersion> versions;
        try
        {
            versions = await custodian.GetKeyVersionsAsync(keyName, cancellationToken).ToListAsync(cancellationToken);
            _lastPublished[keyName] = versions;
        }
        catch (KeyCustodianUnavailableException failure)
        {
            // A cold start has nothing to fall back on, and saying so is the honest answer: the endpoint turns
            // this into the status that says whether to come back.
            if (!_lastPublished.TryGetValue(keyName, out var lastKnown))
                throw;

            LogServingLastKnownKeys(keyName, lastKnown.Count, failure);
            versions = lastKnown;
        }

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
