// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Selects a key for an algorithm and computes a key's thumbprint.
/// </summary>
public static class JsonWebKeyExtensions
{
    /// <summary>
    /// Asynchronously retrieves the first <see cref="JsonWebKey"/> matching an optional algorithm and an optional key
    /// id, with whether a key may be used for the algorithm answered by <paramref name="canPerform"/>: a JWS algorithm
    /// by <see cref="SigningAlgorithmsProvider.CanSign"/>, a JWE key management algorithm by
    /// <see cref="EncryptionAlgorithmsProvider.CanEncrypt"/>, each reading the algorithms registered for it.
    /// </summary>
    /// <remarks>
    /// Order is left to the caller, deliberately. Ranking a declared <c>alg</c> above an undeclared one would
    /// override the order the provider handed down, and that order is load-bearing: a key ring returns the active
    /// key first, so reordering here would pick a key the ring deliberately kept behind - during a rollover, the
    /// newcomer instead of the key clients still expect. Whether a key names its algorithm says nothing about
    /// which key should produce.
    /// </remarks>
    /// <param name="credentials">The asynchronous sequence of <see cref="JsonWebKey"/> objects.</param>
    /// <param name="algorithm">The algorithm to match, or <c>null</c> to not filter by algorithm. Returns <c>null</c>
    /// for <see cref="SigningAlgorithms.None"/>.</param>
    /// <param name="keyId">The <c>kid</c> to match, or <c>null</c> to not filter by key id.</param>
    /// <param name="canPerform">Whether a key may be used for an algorithm.</param>
    /// <returns>The first matching key, or <c>null</c> when the sequence yields none and neither filter was
    /// applied. Throws when a filter was applied but nothing matched, so a pinned key id or a required
    /// algorithm that resolves to no key fails loudly rather than silently downgrading.</returns>
    public static async Task<JsonWebKey?> FirstByAlgorithmAsync(
        this IAsyncEnumerable<JsonWebKey> credentials,
        string? algorithm,
        string? keyId,
        Func<JsonWebKey, string, bool> canPerform)
    {
        if (algorithm is SigningAlgorithms.None)
            return null;

        if (keyId.HasValue())
            credentials = credentials.Where(key => key.KeyId == keyId);

        var passedOver = new List<JsonWebKey>();
        if (algorithm.HasValue())
        {
            credentials = credentials.Where(key =>
            {
                if (canPerform(key, algorithm))
                    return true;

                passedOver.Add(key);
                return false;
            });
        }

        var key = await credentials.FirstOrDefaultAsync();
        if (key is null && (algorithm.HasValue() || keyId.HasValue()))
        {
            // A key passed over for being smaller than RFC 7518 lets the algorithm use is named with its size, so a
            // retired short key reads as what it is rather than as a key that is missing
            var undersized = algorithm.HasValue()
                ? string.Concat(SigningKeyFloor.UndersizedKeys(passedOver, algorithm).Select(found =>
                    $" The key '{found.Key.KeyId}' has {found.Bits} bits, below the {found.Floor} RFC 7518 requires."))
                : string.Empty;

            throw new InvalidOperationException(
                $"No key found for algorithm '{algorithm}' and key id '{keyId}'.{undersized} " +
                $"Ensure the corresponding keys are properly configured and loaded.");
        }
        return key;
    }

    /// <summary>
    /// Computes the JWK Thumbprint of a key per RFC 7638 section 3 and returns the
    /// base64url-encoded form, which is the wire shape used by DPoP <c>cnf.jkt</c> and
    /// the <c>dpop_jkt</c> authorization-request parameter.
    /// </summary>
    /// <param name="key">The key whose thumbprint is computed.</param>
    /// <returns>The base64url-encoded SHA-256 digest of the canonical-JSON form.</returns>
    /// <exception cref="InvalidOperationException">A required member
    /// (per RFC 7638 section 3.2) is missing on the key.</exception>
    public static string ComputeJwkThumbprintBase64Url(this JsonWebKey key)
        => Base64Url.EncodeToString(key.ComputeJwkThumbprint());
}
