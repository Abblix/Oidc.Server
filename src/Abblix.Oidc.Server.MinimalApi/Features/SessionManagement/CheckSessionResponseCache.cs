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
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;

/// <summary>
/// In-memory cache for formatted check-session results. The result objects are stateless (they hold only the HTML
/// template and mint a fresh nonce per execution), so caching them across requests is safe.
/// </summary>
public class CheckSessionResponseCache(IOptions<MemoryCacheOptions> cacheOptions) : ICheckSessionResponseCache
{
    private readonly MemoryCache _cache = new(cacheOptions);

    /// <inheritdoc />
    public Task<IResult> GetOrAddAsync(object key, Func<Task<IResult>> factory)
        => _cache.GetOrCreateAsync<IResult>(key, _ => factory())!;
}
