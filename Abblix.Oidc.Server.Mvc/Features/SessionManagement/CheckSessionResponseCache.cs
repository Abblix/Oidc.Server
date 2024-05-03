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
public class CheckSessionResponseCache : ICheckSessionResponseCache
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CheckSessionResponseCache"/> class with the specified cache options.
    /// </summary>
    /// <param name="cacheOptions">The options to configure the memory cache.</param>
    public CheckSessionResponseCache(IOptions<MemoryCacheOptions> cacheOptions)
    {
        _cache = new MemoryCache(cacheOptions);
    }

    private readonly MemoryCache _cache;

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
