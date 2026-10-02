// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// The checks the deployment's and the issuer's policy put on a JWT Bearer assertion once its signature has
/// been verified: its expiry, signing algorithm, token type and age, and the clock tolerance they are read with.
/// </summary>
/// <remarks>
/// Each check is one link of the handler's validation chain (Chain of Responsibility): it passes the context on
/// or answers with the refusal.
/// </remarks>
/// <param name="logger">Records why an assertion was refused.</param>
/// <param name="issuerProvider">Carries the JWT Bearer options and the per-issuer configuration.</param>
/// <param name="timeProvider">Provides the current time the assertion's age is measured against.</param>
/// <param name="issuerSettings">Carries the issuer's default security profile, which a client without one of its
/// own falls back to.</param>
internal sealed partial class JwtBearerAssertionPolicy(
	ILogger logger,
	IJwtBearerIssuerProvider issuerProvider,
	TimeProvider timeProvider,
	IIssuerSettings issuerSettings)
{
	/// <summary>
	/// Default secure algorithms allowed for JWT signatures when not configured per issuer.
	/// Excludes symmetric (HMAC) and 'none' algorithms for security.
	/// </summary>
	private static readonly string[] DefaultAllowedAlgorithms =
	[
		SigningAlgorithms.RS256,
		SigningAlgorithms.RS384,
		SigningAlgorithms.RS512,

		SigningAlgorithms.ES256,
		SigningAlgorithms.ES384,
		SigningAlgorithms.ES512,

		SigningAlgorithms.PS256,
		SigningAlgorithms.PS384,
		SigningAlgorithms.PS512,
	];

	/// <summary>
	/// The tolerance applied to this client's bearer assertion, resolved in one place so the two checks that
	/// use it - the timestamp comparison and the age limit - cannot disagree about what an unset
	/// value meant.
	/// </summary>
	/// <remarks>
	/// The CLIENT's profile decides, falling back to the deployment's, the way every other reader of
	/// a profile in this codebase resolves one. Reading the server default alone would ignore a
	/// client that asks for a tighter window than the deployment demands.
	/// </remarks>
	public ClockSkew ResolveClockSkew(ClientInfo clientInfo)
		=> issuerProvider.Options.ResolveClockSkew(Profile(clientInfo));

	/// <summary>
	/// The control bundle this client is held to: what the deployment demands of everyone,
	/// tightened by whatever the client names for itself.
	/// </summary>
	private SecurityProfileRequirements Profile(ClientInfo clientInfo)
		=> SecurityProfileRequirements.For(clientInfo, issuerSettings.DefaultSecurityProfile);

	/// <summary>
	/// Validates that the JWT assertion carries an 'exp' (expiration) claim. RFC 7523 Section 3
	/// requires the assertion to contain an 'exp' claim that limits the window during which it can
	/// be used; the generic lifetime check treats a token with neither 'nbf' nor 'exp' as valid, so
	/// this enforces the grant-specific MUST and is also what bounds the replay-cache entry's TTL.
	/// </summary>
	public Result<JwtBearerValidationContext, OidcError> ValidateExpiration(
		JwtBearerValidationContext ctx, ClientInfo clientInfo)
	{
		// Through the guarded reader rather than the accessor: the validator that ran first is
		// whichever one the host registered, which may not have read this claim, and a value the
		// issuer wrote is refused rather than thrown at.
		if (!ctx.Jwt.Payload.TryReadTimestamp(JwtClaimTypes.ExpiresAt, out var expiresAt, out var whyUnreadable))
			return new OidcError(ErrorCodes.InvalidGrant, whyUnreadable);

		if (expiresAt.HasValue)
			return ctx with { ExpiresAt = expiresAt };

		LogMissingExpiration(clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant,
			"The JWT assertion must contain an 'exp' (expiration) claim");
	}

	/// <summary>
	/// Validates that the JWT signing algorithm is in the allowed list.
	/// </summary>
	public Result<JwtBearerValidationContext, OidcError> ValidateAlgorithm(
		JwtBearerValidationContext ctx, ClientInfo clientInfo)
	{
		var allowedAlgorithms = ctx.TrustedIssuer?.AllowedAlgorithms ?? DefaultAllowedAlgorithms;
		var algorithm = ctx.Jwt.Header.Algorithm;

		if (allowedAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
			return ctx;

		LogAlgorithmNotAllowed(algorithm, ctx.Issuer, clientInfo.ClientId);

		return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion uses an unsupported signature algorithm");
	}

	/// <summary>
	/// Validates the JWT token type header against allowed types if configured.
	/// </summary>
	public Result<JwtBearerValidationContext, OidcError> ValidateTokenType(
		JwtBearerValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		if (options.AllowedTokenTypes is not { Length: > 0 } allowedTypes)
			return ctx;

		var tokenType = ctx.Jwt.Header.Type;
		if (allowedTypes.Contains(tokenType, StringComparer.OrdinalIgnoreCase))
			return ctx;

		LogTokenTypeNotAllowed(tokenType ?? "(none)", string.Join(", ", allowedTypes), clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has an unsupported token type");
	}

	/// <summary>
	/// Validates that the JWT is not too old based on MaxJwtAge configuration.
	/// </summary>
	public Result<JwtBearerValidationContext, OidcError> ValidateJwtAge(
		JwtBearerValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		if (options.MaxJwtAge is not { } maxAge)
			return ctx;

		if (!ctx.Jwt.Payload.TryReadTimestamp(JwtClaimTypes.IssuedAt, out var issuedAt, out var whyUnreadable))
			return new OidcError(ErrorCodes.InvalidGrant, whyUnreadable);

		if (issuedAt == null)
		{
			LogMissingIssuedAt(clientInfo.ClientId, ctx.Issuer);

			return new OidcError(ErrorCodes.InvalidGrant,
				"The JWT assertion must contain an 'iat' (issued at) claim when age validation is enabled");
		}

		var now = timeProvider.GetUtcNow();
		var jwtAge = now - issuedAt.Value;

		if (jwtAge <= maxAge + ResolveClockSkew(clientInfo).Past)
			return ctx;

		LogTooOld(issuedAt.Value, jwtAge, maxAge, clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant,
			"The JWT assertion is too old. Please use a freshly issued JWT.");
	}
}
