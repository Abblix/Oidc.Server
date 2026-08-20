// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
