// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.AspNetCore.SessionManagement;

/// <summary>
/// Keeps the formatted check-session page of each issuer in memory until that issuer is released.
/// </summary>
/// <typeparam name="TResult">The transport's result type: an MVC action result or a Minimal API result.</typeparam>
/// <param name="cacheOptions">The options to configure the memory cache.</param>
public class CheckSessionResponseCache<TResult>(IOptions<MemoryCacheOptions> cacheOptions)
    : ICheckSessionResponseCache<TResult> where TResult : class
{
    private readonly MemoryCache _cache = new(cacheOptions);

    /// <inheritdoc />
    public Task<TResult> GetOrAddAsync(object key, Func<Task<TResult>> factory, CancellationToken released)
        => _cache.GetOrCreateAsync<TResult>(key, entry =>
        {
            entry.AddExpirationToken(new CancellationChangeToken(released));
            return factory();
        })!;
}
