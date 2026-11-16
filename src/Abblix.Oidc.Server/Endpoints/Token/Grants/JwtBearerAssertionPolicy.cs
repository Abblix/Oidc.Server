// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// The checks the deployment's and the issuer's policy put on a JWT Bearer assertion once its signature has
/// been verified: its expiry, signing algorithm, token type, age, replay and scopes, and the clock tolerance they
/// are read with.
/// </summary>
/// <remarks>
/// Each check is one link of the handler's validation chain (Chain of Responsibility): it passes the context on
/// or answers with the refusal.
/// </remarks>
/// <param name="logger">Records why an assertion was refused.</param>
/// <param name="issuerProvider">Carries the JWT Bearer options and the per-issuer configuration.</param>
/// <param name="timeProvider">Provides the current time the assertion's age is measured against.</param>
/// <param name="replayCache">Records each jti until its assertion expires (RFC 7523 Section 3).</param>
/// <param name="requestInfoProvider">Names the address a replay came from.</param>
internal sealed partial class JwtBearerAssertionPolicy(
	ILogger logger,
	IJwtBearerIssuerProvider issuerProvider,
	TimeProvider timeProvider,
	IReplayCache replayCache,
	IRequestInfoProvider requestInfoProvider)
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
	public ClockSkew ResolveClockSkew(TenantDefinition tenant, ClientInfo clientInfo)
		=> issuerProvider.Options.ResolveClockSkew(Profile(tenant, clientInfo));

	/// <summary>
	/// The control bundle this client is held to: what the deployment demands of everyone,
	/// tightened by whatever the client names for itself.
	/// </summary>
	private static SecurityProfileRequirements Profile(TenantDefinition tenant, ClientInfo clientInfo)
		=> SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile);

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
	/// Validates that the JWT signing algorithm is in the trusted issuer's allowed list. The client's security profile
	/// bounded the algorithm already, where the assertion was validated.
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
	/// Validates the JWT token type header against the allowed types, or, when the deployment lists none, refuses a
	/// type naming another kind of token.
	/// </summary>
	/// <remarks>
	/// RFC 7523 defines no type for an assertion, so an assertion without one is accepted either way. Without a
	/// list of its own a deployment also accepts the generic type or one this server does not know, while an
	/// access token or a logout token of a trusted issuer is refused rather than taken as a grant (RFC 8725
	/// Section 3.11). A listed type matches in either spelling of its <c>application/</c> prefix, as RFC 7515
	/// Section 4.1.9 makes them one type.
	/// </remarks>
	public Result<JwtBearerValidationContext, OidcError> ValidateTokenType(
		JwtBearerValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		var tokenType = ctx.Jwt.Header.Type;
		if (options.AllowedTokenTypes is not { Length: > 0 } allowedTypes)
		{
			if (JwtTypes.IsPermitted(tokenType))
				return ctx;

			LogTokenOfAnotherKind(tokenType, clientInfo.ClientId, ctx.Issuer);
			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has an unsupported token type");
		}

		if (tokenType is null || allowedTypes.Any(allowed => JwtTypeName.Matches(tokenType, allowed)))
			return ctx;

		LogTokenTypeNotAllowed(tokenType, string.Join(", ", allowedTypes), clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has an unsupported token type");
	}

	/// <summary>
	/// Validates that the JWT is not too old based on MaxJwtAge configuration.
	/// </summary>
	public Result<JwtBearerValidationContext, OidcError> ValidateJwtAge(
		TenantDefinition tenant,
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

		if (jwtAge <= maxAge + ResolveClockSkew(tenant, clientInfo).Past)
			return ctx;

		LogTooOld(issuedAt.Value, jwtAge, maxAge, clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant,
			"The JWT assertion is too old. Please use a freshly issued JWT.");
	}

	/// <summary>
	/// Validates that requested scopes are allowed for the issuer.
	/// </summary>
	public Result<JwtBearerValidationContext, OidcError> ValidateScopes(
		JwtBearerValidationContext ctx, string[]? scope)
	{
		if (ctx is not { TrustedIssuer.AllowedScopes: { Length: > 0 } allowedScopes} || scope is null)
			return ctx;

		var invalidScopes = scope.Except(allowedScopes).ToArray();
		if (invalidScopes.Length == 0)
			return ctx;

		LogScopesNotAllowed(Sanitized.Values(invalidScopes), ctx.Issuer);

		return new OidcError(
			ErrorCodes.InvalidScope,
			$"The following scopes are not allowed for this issuer: {string.Join(", ", invalidScopes)}");
	}

	/// <summary>
	/// Validates that the JWT has not been used before (replay protection per RFC 7523 Section 3).
	/// </summary>
	public async Task<Result<JwtBearerValidationContext, OidcError>> ValidateReplayAsync(
		JwtBearerValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		if (!options.RequireJti)
			return ctx;

		var jti = ctx.Jwt.Payload.JwtId;
		if (string.IsNullOrWhiteSpace(jti))
		{
			LogMissingJti(clientInfo.ClientId, ctx.Issuer);
			return new OidcError(ErrorCodes.InvalidGrant,
				"The JWT assertion must contain a 'jti' (JWT ID) claim for replay protection");
		}

		// Single atomic reserve-and-check: record the jti keyed to the assertion's own 'exp' (which
		// ValidateExpiration guarantees is present and carries on the context) and treat "already
		// present" as a replay. One call avoids both the lost-TTL bug of a separate mark step and
		// the read-then-write race. An assertion carrying no expiry names no window to remember it for, so the
		// identifier is held for the fallback the cache publishes.
		var expiresAt = ctx.ExpiresAt ?? timeProvider.GetUtcNow() + ConfiguredReplayCache.DefaultExpiration;
		if (!await replayCache.TryReserveAsync(jti, expiresAt))
		{
			LogReplayDetected(jti, clientInfo.ClientId, ctx.Issuer, ctx.Jwt.Header.KeyId ?? "none", requestInfoProvider.RemoteIpAddress);
			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has already been used");
		}

		return ctx;
	}
}
