// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Provides reusable functionality for fetching JSON Web Key Sets (JWKS) from remote URIs
/// with SSRF protection and consistent error handling.
/// </summary>
public static partial class SecureHttpFetcherExtensions
{
	/// <summary>
	/// Fetches JSON Web Keys from a JWKS URI with SSRF protection and optional filtering.
	/// </summary>
	/// <param name="secureFetcher">HTTP fetcher with SSRF protection and caching.</param>
	/// <param name="jwksUri">The URI to fetch the JWKS from.</param>
	/// <param name="logger">Logger for recording fetch operations and errors.</param>
	/// <param name="entityId">The identifier of the entity (client ID or issuer) for logging.</param>
	/// <param name="entityType">The type of entity (e.g., "client" or "issuer") for logging.</param>
	/// <returns>
	/// An async enumerable of JSON Web Keys from the JWKS endpoint.
	/// Returns empty if fetching fails or the JWKS is invalid.
	/// </returns>
	public static async IAsyncEnumerable<JsonWebKey> FetchKeysAsync(
		this ISecureHttpFetcher secureFetcher,
		Uri jwksUri,
		ILogger logger,
		string entityId,
		string entityType)
	{
		LogFetchingJwks(logger, entityType, entityId, jwksUri);

		var result = await secureFetcher.FetchAsync<JsonWebKeySet>(jwksUri);

		var jwksKeys = result.Match(
			jwks =>
			{
				if (jwks is { Keys: { Length: > 0 } keys })
					return keys.ToAsyncEnumerable();

				LogJwksEmpty(logger, entityType, entityId, jwksUri);

				return AsyncEnumerable.Empty<JsonWebKey>();

			},
			error =>
			{
				LogJwksFetchFailed(logger, entityType, entityId, jwksUri, error.ErrorDescription);

				return AsyncEnumerable.Empty<JsonWebKey>();
			});

		await foreach (var key in jwksKeys)
		{
			yield return key;
		}
	}

	/// <summary>
	/// Resolves the keys a party publishes, in the two forms a party may publish them: inline in its
	/// registration, and at a JWKS URI. Both may be present, and the inline keys come first.
	/// </summary>
	/// <param name="serviceProvider">Used to resolve <see cref="ISecureHttpFetcher"/>, which is scoped while
	/// the providers calling this are not, so a scope is created per call rather than held.</param>
	/// <param name="jwks">The key set held in the party's own registration, if any.</param>
	/// <param name="jwksUri">The URI the party publishes its key set at, if any.</param>
	/// <param name="logger">Logger for recording fetch operations and errors.</param>
	/// <param name="entityId">The identifier of the party, for logging.</param>
	/// <param name="entityType">What kind of party it is. Must be a value from <see cref="KeySetOwners"/>:
	/// besides labelling the log, it is the service key under which this consumer's cached fetcher is
	/// registered, so the same value selects the cache lifetime that consumer was given.</param>
	/// <returns>The inline keys followed by the fetched ones. Empty when the party declares neither.</returns>
	/// <remarks>
	/// The fetch itself is SSRF-protected and cached by the decorators around <see cref="ISecureHttpFetcher"/>,
	/// so a caller gets both without arranging either.
	/// </remarks>
	public static async IAsyncEnumerable<JsonWebKey> ResolveKeysAsync(
		this IServiceProvider serviceProvider,
		JsonWebKeySet? jwks,
		Uri? jwksUri,
		ILogger logger,
		string entityId,
		string entityType)
	{
		if (jwks != null)
		{
			foreach (var key in jwks.Keys)
				yield return key;
		}

		if (jwksUri == null)
			yield break;

		using var scope = serviceProvider.CreateScope();
		var secureFetcher = scope.ServiceProvider.GetRequiredKeyedService<ISecureHttpFetcher>(entityType);

		await foreach (var key in secureFetcher.FetchKeysAsync(jwksUri, logger, entityId, entityType))
		{
			yield return key;
		}
	}
}
