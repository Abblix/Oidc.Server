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
using Microsoft.Extensions.Options;

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
/// <param name="options">Supplies <see cref="SecureHttpFetchOptions.RefetchInterval"/>, read on each fetch so a
/// host changing it at runtime is honored.</param>
/// <param name="fetches">Shares one fetch of a URI among the callers asking for it at once, and serves a finished
/// fetch, succeeded or failed, for the hold that follows it. Instances of this decorator are created per resolution,
/// so the loader is the container's single one, and consumers asking for the same URI share its fetches whenever
/// they hold it for the same time.</param>
public class CachingSecureHttpFetcherDecorator(
	ISecureHttpFetcher inner,
	IMemoryCache cache,
	TimeSpan cacheDuration,
	IOptionsMonitor<SecureHttpFetchOptions> options,
	CoalescingLoader<string, object> fetches) : ISecureHttpFetcher
{
	/// <inheritdoc />
	/// <remarks>
	/// The URI is decided by whoever registered it and the number of fetches by whoever sends requests, so a document
	/// that is not held is fetched once for all the requests arriving together, and a fetch that failed answers the
	/// requests after it for the hold rather than sending each of them to a server that is down.
	/// </remarks>
	public async Task<Result<T, OidcError>> FetchAsync<T>(Uri uri, bool refetch = false)
	{
		if (refetch)
			return await RefetchAsync<T>(uri);

		var cacheKey = CacheKey(uri);

		if (cache.TryGetValue<T>(cacheKey, out var cached) && !ReferenceEquals(cached, null))
			return cached;

		var hold = HoldFor();
		return (Result<T, OidcError>)await fetches.LoadAsync(
			FetchKey<T>(uri, hold),
			async _ =>
			{
				var result = await inner.FetchAsync<T>(uri);
				Store(cacheKey, result);
				return result;
			},
			hold);
	}

	/// <summary>
	/// Fetches the URI past the copy held, at most once per <see cref="SecureHttpFetchOptions.RefetchInterval"/>.
	/// </summary>
	/// <remarks>
	/// The fetch itself is what is held, so every caller inside the interval awaits the same one: requests arriving
	/// together after a key rotation all see the new set. It is held apart from an ordinary fetch, so a fetch that just
	/// read the old set does not answer the refetch a rotated key asks for.
	/// </remarks>
	private async Task<Result<T, OidcError>> RefetchAsync<T>(Uri uri)
	{
		var hold = HoldFor();
		return (Result<T, OidcError>)await fetches.LoadAsync(
			RefetchKey<T>(uri, hold),
			async _ => await FetchAnewAsync<T>(uri),
			hold);
	}

	/// <summary>
	/// How long one fetch answers the next: the refetch interval, but never longer than the copy itself is held.
	/// </summary>
	/// <remarks>
	/// A refetch held past the copy's own lifetime would serve a key set older than the copy, so a key its signer
	/// removed, and that a fresh copy no longer carries, would verify again for whoever names an unknown key. With
	/// caching off every fetch is already fresh, and nothing is held past the callers sharing it.
	/// </remarks>
	private TimeSpan HoldFor()
	{
		var interval = options.CurrentValue.RefetchInterval;
		return interval < cacheDuration ? interval : cacheDuration;
	}

	/// <summary>
	/// Fetches the URI past the copy held, replacing that copy only when the fetch succeeds.
	/// </summary>
	/// <remarks>
	/// Anyone able to send a token can cause a refetch, so a failed one serves the copy that worked rather than
	/// dropping it: otherwise a caller could make a URI that is briefly unreachable cost its owner every key it has.
	/// </remarks>
	private async Task<Result<T, OidcError>> FetchAnewAsync<T>(Uri uri)
	{
		var cacheKey = CacheKey(uri);
		var result = await inner.FetchAsync<T>(uri);
		if (result.TryGetSuccess(out _))
		{
			Store(cacheKey, result);
			return result;
		}

		return cache.TryGetValue<T>(cacheKey, out var held) && !ReferenceEquals(held, null) ? held : result;
	}

	private void Store<T>(string cacheKey, Result<T, OidcError> result)
	{
		// A non-positive lifetime means caching off, and it has to be handled here: MemoryCache does not read
		// TimeSpan.Zero as "do not store", so a host zeroing the setting to force fresh fetches would get a
		// stored entry instead of the behavior it asked for.
		if (result.TryGetSuccess(out var value) && cacheDuration > TimeSpan.Zero)
		{
			// Keyed on the URI alone, because one address is one document. What differs between consumers is
			// how long it may be held, and that is fixed per instance rather than per call.
			cache.Set(cacheKey, value, cacheDuration);
		}
	}

	private static string CacheKey(Uri uri)
		=> $"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(Features)}.{nameof(SecureHttpFetch)}:{uri}";

	// Apart from the document itself, so a held fetch lasts its interval whatever the document's lifetime; typed, since
	// one URI read as two types is two fetches; and carrying the hold, since the loader is shared by every consumer and a
	// consumer caching for less, or not at all, must not be answered with a fetch held for another one's interval
	private static string FetchKey<T>(Uri uri, TimeSpan hold)
		=> $"{CacheKey(uri)}:fetch:{typeof(T).FullName}:{hold.Ticks}";

	private static string RefetchKey<T>(Uri uri, TimeSpan hold)
		=> $"{CacheKey(uri)}:refetch:{typeof(T).FullName}:{hold.Ticks}";
}
