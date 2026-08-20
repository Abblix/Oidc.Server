// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Features.SessionManagement;

/// <summary>
/// Represents a cache for storing and retrieving CheckSession responses asynchronously.
/// </summary>
/// <remarks>
/// This cache is used to store CheckSession responses for quick retrieval, reducing the need to recompute them
/// for the same input key.
/// </remarks>
/// <param name="cacheOptions">The options to configure the memory cache.</param>
public class CheckSessionResponseCache(IOptions<MemoryCacheOptions> cacheOptions) : ICheckSessionResponseCache
{
    private readonly MemoryCache _cache = new(cacheOptions);

    /// <summary>
    /// Gets an ActionResult from the cache with the specified key, or adds it to the cache if not present.
    /// </summary>
    /// <param name="key">The key used to identify the item in the cache.</param>
    /// <param name="factory">
    /// A delegate that provides the ActionResult to be added to the cache if it doesn't exist.
    /// </param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> representing the asynchronous operation. The task result contains
    /// the cached or newly generated ActionResult.
    /// </returns>
    public Task<ActionResult> GetOrAddAsync(object key, Func<Task<ActionResult>> factory)
        => _cache.GetOrCreateAsync<ActionResult>(key, _ => factory())!;
}
