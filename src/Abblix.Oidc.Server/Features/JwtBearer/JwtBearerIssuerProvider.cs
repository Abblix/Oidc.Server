// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
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
/// <param name="logger">Logger for recording JWKS fetch operations and errors.</param>
/// <param name="oidcOptions">OIDC configuration options containing JWT Bearer trusted issuers.</param>
/// <param name="replayCache">Cache for JWT replay protection per RFC 7523 Section 3.</param>
/// <param name="secureFetcher">HTTP fetcher with SSRF protection and caching.</param>
/// <param name="timeProvider">Dates the fallback retention window for an assertion without an
/// expiry.</param>
public partial class JwtBearerIssuerProvider(
	ILogger<JwtBearerIssuerProvider> logger,
	IOptionsMonitor<OidcOptions> oidcOptions,
	IReplayCache replayCache,
	[FromKeyedServices(KeySetOwners.Issuer)] ISecureHttpFetcher secureFetcher,
	TimeProvider timeProvider) : IJwtBearerIssuerProvider
{
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
			LogIssuerNotTrusted(issuer);

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
			LogInvalidIssuerUri(issuer);
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
			       issuerUri.AbsolutePath == trustedUri.AbsolutePath;
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
			LogSigningKeysForUntrustedIssuer(issuer);
			yield break;
		}

		var keys = secureFetcher.FetchKeysAsync(trustedIssuer.JwksUri, logger, issuer, KeySetOwners.Issuer);
		await foreach (var key in keys.Where(k => k.Usage is null or PublicKeyUsages.Signature))
		{
			yield return key;
		}
	}

	/// <inheritdoc />
	public async Task<bool> IsReplayedAsync(string jti, DateTimeOffset? expiresAt)
		// An assertion carrying no expiry names no window to remember it for, so the identifier is
		// held for the fallback the cache publishes. The guess is made here, where the reason for it
		// is visible, rather than inside the cache where a caller cannot see what it got.
		=> !await replayCache.TryReserveAsync(
			jti,
			expiresAt ?? timeProvider.GetUtcNow() + ReplayPrevention.ConfiguredReplayCache.DefaultExpiration);
}
