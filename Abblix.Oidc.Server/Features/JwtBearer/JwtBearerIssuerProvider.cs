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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.JwtBearer;

/// <summary>
/// Default implementation of <see cref="IJwtBearerIssuerProvider"/> that loads trusted issuers
/// from <see cref="OidcOptions.JwtBearer"/> configuration, fetches JWKS with SSRF protection,
/// and provides JWT replay protection.
/// </summary>
/// <param name="oidcOptions">OIDC configuration options containing JWT Bearer trusted issuers.</param>
/// <param name="replayCache">Cache for JWT replay protection per RFC 7523 Section 5.2.</param>
/// <param name="secureFetcher">HTTP fetcher with SSRF protection and JWKS caching.</param>
/// <param name="logger">Logger for recording JWKS fetch operations and errors.</param>
public class JwtBearerIssuerProvider(
	IOptionsMonitor<OidcOptions> oidcOptions,
	IJwtReplayCache replayCache,
	[FromKeyedServices(JwtBearerIssuerProvider.SecureHttpFetcherKey)] ISecureHttpFetcher secureFetcher,
	ILogger<JwtBearerIssuerProvider> logger) : IJwtBearerIssuerProvider
{
	/// <summary>
	/// The keyed service key used to resolve the caching <see cref="ISecureHttpFetcher"/> for JWKS fetching.
	/// </summary>
	public const string SecureHttpFetcherKey = "JwtBearerJwks";

	/// <inheritdoc />
	public JwtBearerOptions Options => oidcOptions.CurrentValue.JwtBearer;

	/// <summary>
	/// Determines whether the specified issuer is trusted for JWT Bearer assertions.
	/// Checks against the configured list of trusted issuers in <see cref="OidcOptions.JwtBearer"/>.
	/// </summary>
	/// <param name="issuer">The issuer identifier from the JWT's 'iss' claim.</param>
	/// <returns>
	/// A task that completes with true if the issuer is in the trusted issuers list; otherwise, false.
	/// </returns>
	public Task<bool> IsTrustedIssuerAsync(string issuer)
	{
		var trustedIssuer = FindTrustedIssuer(issuer);

		if (trustedIssuer == null)
		{
			logger.LogDebug("Issuer {Issuer} is not in the trusted issuers list", issuer);
		}

		return Task.FromResult(trustedIssuer != null);
	}

	/// <inheritdoc />
	public Task<TrustedIssuer?> GetTrustedIssuerAsync(string issuer) =>
		Task.FromResult(FindTrustedIssuer(issuer));

	/// <summary>
	/// Finds a trusted issuer by matching the issuer identifier.
	/// Uses URI-based comparison for proper scheme/host handling per RFC 3986.
	/// </summary>
	private TrustedIssuer? FindTrustedIssuer(string issuer)
	{
		if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
		{
			logger.LogDebug("Invalid issuer URI format: {Issuer}", issuer);
			return null;
		}

		return oidcOptions.CurrentValue.JwtBearer.TrustedIssuers.FirstOrDefault(ti =>
		{
			if (!Uri.TryCreate(ti.Issuer, UriKind.Absolute, out var trustedUri))
				return false;

			// RFC 3986: scheme and host are case-insensitive, path is case-sensitive
			return string.Equals(issuerUri.Scheme, trustedUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
			       string.Equals(issuerUri.Host, trustedUri.Host, StringComparison.OrdinalIgnoreCase) &&
			       issuerUri.Port == trustedUri.Port &&
			       string.Equals(issuerUri.AbsolutePath, trustedUri.AbsolutePath, StringComparison.Ordinal);
		});
	}

	/// <summary>
	/// Resolves the signing keys for a trusted issuer by fetching the JWKS from the configured JWKS URI
	/// with SSRF (Server-Side Request Forgery) protection.
	/// </summary>
	/// <param name="issuer">The issuer identifier from the JWT's 'iss' claim.</param>
	/// <returns>
	/// An async enumerable of JSON Web Keys from the issuer's JWKS endpoint.
	/// Returns empty if the issuer is not trusted or if fetching JWKS fails.
	/// </returns>
	/// <remarks>
	/// This implementation:
	/// - Looks up the issuer in the trusted issuers configuration
	/// - Fetches the JWKS from the configured JwksUri using ISecureHttpFetcher (SSRF protected)
	/// - JWKS responses are cached according to <see cref="JwtBearerOptions.JwksCacheDuration"/>
	/// - Filters keys to return only those suitable for signature verification
	/// - Logs warnings if JWKS fetching fails
	/// </remarks>
	public async IAsyncEnumerable<JsonWebKey> GetSigningKeysAsync(string issuer)
	{
		var trustedIssuer = FindTrustedIssuer(issuer);

		if (trustedIssuer == null)
		{
			logger.LogWarning("Attempted to get signing keys for untrusted issuer {Issuer}", issuer);
			yield break;
		}

		var keys = secureFetcher.FetchKeysAsync(trustedIssuer.JwksUri, logger, issuer, "issuer");
		await foreach (var key in keys.Where(k => k.Usage is null or PublicKeyUsages.Signature))
		{
			yield return key;
		}
	}

	/// <inheritdoc />
	public Task<bool> IsReplayedAsync(string jti) => replayCache.IsReplayedAsync(jti);

	/// <inheritdoc />
	public Task MarkAsUsedAsync(string jti, DateTimeOffset? expiresAt) => replayCache.MarkAsUsedAsync(jti, expiresAt);
}
