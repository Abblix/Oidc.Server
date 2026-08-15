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

using Abblix.Jwt;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Provides extensions for asynchronous operations on a sequence of <see cref="JsonWebKey"/> objects.
/// </summary>
public static class JsonWebKeyExtensions
{
    /// <summary>
    /// Asynchronously retrieves the first <see cref="JsonWebKey"/> able to perform the specified algorithm.
    /// </summary>
    /// <remarks>
    /// A key qualifies by declaring the algorithm, or - when it declares none, which RFC 7517 section 4.4 permits
    /// and a certificate-imported key always does - by its material being able to perform it, per
    /// <see cref="Abblix.Jwt.JsonWebKeyExtensions.SupportsAlgorithm"/>.
    /// <para>
    /// Order is left to the caller, deliberately. Ranking a declared <c>alg</c> above an undeclared one would
    /// override the order the provider handed down, and that order is load-bearing: a key ring returns the active
    /// key first, so reordering here would pick a key the ring deliberately kept behind - during a rollover, the
    /// newcomer instead of the key clients still expect. Whether a key names its algorithm says nothing about
    /// which key should produce.
    /// </para>
    /// </remarks>
    /// <param name="credentials">The asynchronous sequence of <see cref="JsonWebKey"/> objects.</param>
    /// <param name="algorithm">The algorithm to match. Returns null if <see cref="SigningAlgorithms.None"/> is provided.</param>
    /// <returns>The first <see cref="JsonWebKey"/> able to perform the algorithm.</returns>
    public static async Task<JsonWebKey?> FirstByAlgorithmAsync(
        this IAsyncEnumerable<JsonWebKey> credentials,
        string? algorithm)
    {
        if (algorithm is null or SigningAlgorithms.None)
            return null;

        if (algorithm.HasValue())
        {
            credentials = credentials.Where(key => key.CanPerform(algorithm));
        }

        var key = await credentials.FirstOrDefaultAsync();
        if (key == null)
        {
            throw new InvalidOperationException(
                $"No signing key found for algorithm '{algorithm}'. " +
                $"Ensure signing certificates are properly configured and loaded.");
        }
        return key;
    }

    /// <summary>
    /// Asynchronously retrieves the first <see cref="JsonWebKey"/> matching an optional algorithm and an
    /// optional key id. This is the key-id-aware sibling of <see cref="FirstByAlgorithmAsync(IAsyncEnumerable{JsonWebKey}, string?)"/>:
    /// signing passes the token's <c>alg</c> and pinned <c>kid</c>; encryption passes a <c>null</c> algorithm
    /// (the key-management <c>alg</c> is derived from the chosen key afterwards) and only the pinned <c>kid</c>.
    /// </summary>
    /// <param name="credentials">The asynchronous sequence of <see cref="JsonWebKey"/> objects.</param>
    /// <param name="algorithm">The algorithm to match, or <c>null</c> to not filter by algorithm. A key qualifies
    /// by declaring it or, declaring none, by being able to perform it. Returns <c>null</c> for
    /// <see cref="SigningAlgorithms.None"/>.</param>
    /// <param name="keyId">The <c>kid</c> to match, or <c>null</c> to not filter by key id.</param>
    /// <returns>The first matching key, or <c>null</c> when the sequence yields none and neither filter was
    /// applied. Throws when a filter was applied but nothing matched, so a pinned key id or a required
    /// algorithm that resolves to no key fails loudly rather than silently downgrading.</returns>
    public static async Task<JsonWebKey?> FirstByAlgorithmAsync(
        this IAsyncEnumerable<JsonWebKey> credentials,
        string? algorithm,
        string? keyId)
    {
        if (algorithm is SigningAlgorithms.None)
            return null;

        if (keyId.HasValue())
            credentials = credentials.Where(key => key.KeyId == keyId);

        if (algorithm.HasValue())
        {
            credentials = credentials.Where(key => key.CanPerform(algorithm));
        }

        var key = await credentials.FirstOrDefaultAsync();
        if (key is null && (algorithm.HasValue() || keyId.HasValue()))
        {
            throw new InvalidOperationException(
                $"No key found for algorithm '{algorithm}' and key id '{keyId}'. " +
                $"Ensure the corresponding keys are properly configured and loaded.");
        }
        return key;
    }

    /// <summary>
    /// Whether a key may be used for an algorithm: it either declares that algorithm, or declares none and its
    /// material can perform it.
    /// </summary>
    /// <remarks>
    /// RFC 7517 section 4.4 makes <c>alg</c> OPTIONAL, and a key imported from a certificate never carries one.
    /// Treating an undeclared algorithm as a disqualification would drop exactly those keys; treating it as
    /// "anything goes" would hand an RSA key to an ECDSA algorithm and fail at the signature instead of at the
    /// selection. Asking the material settles it, and RFC 7518 sections 3.1 and 3.4 make the answer exact.
    /// </remarks>
    private static bool CanPerform(this JsonWebKey key, string algorithm)
        => key.Algorithm is not null ? key.Algorithm == algorithm : key.SupportsAlgorithm(algorithm);
}
