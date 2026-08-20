// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Memory;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// A decorator for <see cref="ISecureHttpFetcher"/> that adds caching capabilities.
/// Caches successful responses for the configured duration to reduce network calls
/// and improve performance.
/// </summary>
/// <param name="inner">The inner fetcher to decorate.</param>
/// <param name="cache">The memory cache to store responses.</param>
/// <param name="cacheDuration">How long a successfully fetched document is held. Supplied per consumer at
/// registration rather than read from a shared setting, so each one states the staleness it can live with:
/// a key set backing token issuance and one backing an occasional signature check do not want the same
/// lifetime, and the transport contract stays free of the caller's policy.</param>
public class CachingSecureHttpFetcherDecorator(
	ISecureHttpFetcher inner,
	IMemoryCache cache,
	TimeSpan cacheDuration) : ISecureHttpFetcher
{
	/// <inheritdoc />
	public async Task<Result<T, OidcError>> FetchAsync<T>(Uri uri)
	{
		var cacheKey = $"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(Features)}.{nameof(SecureHttpFetch)}:{uri}";

		if (cache.TryGetValue<T>(cacheKey, out var cached) && !ReferenceEquals(cached, null))
			return cached;

		var result = await inner.FetchAsync<T>(uri);

		// A non-positive lifetime means caching off, and it has to be handled here: MemoryCache does not read
		// TimeSpan.Zero as "do not store", so a host zeroing the setting to force fresh fetches would get a
		// stored entry instead of the behaviour it asked for.
		if (result.TryGetSuccess(out var value) && cacheDuration > TimeSpan.Zero)
		{
			// Keyed on the URI alone, because one address is one document. What differs between consumers is
			// how long it may be held, and that is fixed per instance rather than per call.
			cache.Set(cacheKey, value, cacheDuration);
		}

		return result;
	}
}
