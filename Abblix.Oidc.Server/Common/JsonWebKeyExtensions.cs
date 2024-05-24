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
    /// </summary>
    /// <param name="credentials">The asynchronous sequence of <see cref="JsonWebKey"/> objects.</param>
    /// <param name="alg">The algorithm to match. Returns null if <see cref="SigningAlgorithms.None"/> is provided.</param>
    /// <returns>The first <see cref="JsonWebKey"/> with the specified algorithm or null if not found.</returns>

    public static async Task<JsonWebKey?> FirstByAlgorithmAsync(this IAsyncEnumerable<JsonWebKey> credentials, string? alg)
    {
        if (alg == SigningAlgorithms.None)
            return null;

        if (alg.HasValue())
            credentials = credentials.Where(key => key.Algorithm == alg);

        return await credentials.FirstOrDefaultAsync();
    }
}
