// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
