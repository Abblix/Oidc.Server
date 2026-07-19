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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// A decorator for <see cref="ISecureHttpFetcher"/> that adds caching capabilities.
/// Caches successful responses for the configured duration to reduce network calls
/// and improve performance.
/// </summary>
/// <param name="inner">The inner fetcher to decorate.</param>
/// <param name="cache">The memory cache to store responses.</param>
/// <param name="oidcOptions">OIDC options containing the cache duration configuration.</param>
public class CachingSecureHttpFetcherDecorator(
	ISecureHttpFetcher inner,
	IMemoryCache cache,
	IOptionsMonitor<OidcOptions> oidcOptions) : ISecureHttpFetcher
{
	/// <inheritdoc />
	public async Task<Result<T, OidcError>> FetchAsync<T>(Uri uri)
	{
		var cacheKey = $"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(Features)}.{nameof(SecureHttpFetch)}:{uri}";

		if (cache.TryGetValue<T>(cacheKey, out var cached) && !ReferenceEquals(cached, null))
			return cached;

		var result = await inner.FetchAsync<T>(uri);

		if (result.TryGetSuccess(out var value))
		{
			cache.Set(cacheKey, value, oidcOptions.CurrentValue.JwtBearer.JwksCacheDuration);
		}

		return result;
	}
}
