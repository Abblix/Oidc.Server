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

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;

/// <summary>
/// Caches formatted check-session results keyed by the response's cache key.
/// </summary>
public interface ICheckSessionResultCache
{
    /// <summary>
    /// Gets the result for the key from the cache, or produces and stores it via <paramref name="factory"/>.
    /// </summary>
    /// <param name="key">The key identifying the cached result.</param>
    /// <param name="factory">Produces the result when the key is not yet cached.</param>
    /// <returns>The cached or newly produced <see cref="IResult"/>.</returns>
    Task<IResult> GetOrAddAsync(object key, Func<Task<IResult>> factory);
}
