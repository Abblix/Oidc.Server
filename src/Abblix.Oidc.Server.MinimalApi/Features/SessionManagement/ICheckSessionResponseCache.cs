// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;

/// <summary>
/// Caches formatted check-session results keyed by the response's cache key.
/// </summary>
public interface ICheckSessionResponseCache
{
    /// <summary>
    /// Gets the result for the key from the cache, or produces and stores it via <paramref name="factory"/>.
    /// </summary>
    /// <param name="key">The key identifying the cached result.</param>
    /// <param name="factory">Produces the result when the key is not yet cached.</param>
    /// <returns>The cached or newly produced <see cref="IResult"/>.</returns>
    Task<IResult> GetOrAddAsync(object key, Func<Task<IResult>> factory);
}
