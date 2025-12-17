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
    /// Asynchronously retrieves the first <see cref="JsonWebKey"/> with the specified algorithm from the sequence.
    /// Prioritizes keys with exact algorithm match, then falls back to algorithm-agnostic keys (Algorithm == null)
    /// per RFC 7517, which allows keys without 'alg' parameter to be used with any compatible algorithm.
    /// </summary>
    /// <param name="credentials">The asynchronous sequence of <see cref="JsonWebKey"/> objects.</param>
    /// <param name="algorithm">The algorithm to match. Returns null if <see cref="SigningAlgorithms.None"/> is provided.</param>
    /// <returns>The first <see cref="JsonWebKey"/> with the specified algorithm or null if not found.</returns>

    public static async Task<JsonWebKey?> FirstByAlgorithmAsync(
        this IAsyncEnumerable<JsonWebKey> credentials,
        string? algorithm)
    {
        if (algorithm is null or SigningAlgorithms.None)
            return null;

        if (algorithm.HasValue())
        {
            // Prioritize exact algorithm match, then fall back to algorithm-agnostic keys (Algorithm == null)
            credentials = credentials
                .Where(key => key.Algorithm == algorithm || key.Algorithm == null)
                .OrderBy(key => key.Algorithm == algorithm ? 0 : 1); // Exact match first (0), then null (1)
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
}
