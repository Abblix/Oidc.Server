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

using Abblix.Jwt;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Provides reusable functionality for fetching JSON Web Key Sets (JWKS) from remote URIs
/// with SSRF protection and consistent error handling.
/// </summary>
public static class SecureHttpFetcherExtensions
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
		logger.LogDebug("Fetching JWKS for {EntityType} {EntityId} from {JwksUri}",
			entityType, entityId, jwksUri);

		var result = await secureFetcher.FetchAsync<JsonWebKeySet>(jwksUri);

		var jwksKeys = result.Match(
			jwks =>
			{
				if (jwks is { Keys: { Length: > 0 } keys })
					return keys.ToAsyncEnumerable();

				logger.LogWarning("JWKS for {EntityType} {EntityId} from {JwksUri} is empty or invalid",
					entityType, entityId, jwksUri);
				return AsyncEnumerable.Empty<JsonWebKey>();

			},
			error =>
			{
				logger.LogError("Failed to fetch JWKS for {EntityType} {EntityId} from {JwksUri}: {Error}",
					entityType, entityId, jwksUri, error.ErrorDescription);
				return AsyncEnumerable.Empty<JsonWebKey>();
			});

		await foreach (var key in jwksKeys)
		{
			yield return key;
		}
	}
}
