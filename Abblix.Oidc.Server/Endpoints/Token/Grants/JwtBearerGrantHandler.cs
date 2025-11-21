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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the JWT Bearer grant type per RFC 7523, allowing clients to exchange a JWT assertion
/// for an access token. This grant type is used when a client has obtained a JWT from a trusted
/// identity provider and wants to exchange it for an access token at this authorization server.
/// </summary>
/// <remarks>
/// The JWT Bearer grant type is specified in RFC 7523 and is commonly used in scenarios such as:
/// - Service-to-service authentication with pre-existing trust relationships
/// - Token exchange between federated identity providers
/// - API-to-API communication where the calling service has a JWT from an identity provider
/// - Single sign-on (SSO) across different domains or organizations
///
/// The JWT assertion must contain specific claims per RFC 7523 Section 3:
/// - iss (issuer): Identifies the principal that issued the JWT
/// - sub (subject): Identifies the principal that is the subject of the JWT
/// - aud (audience): Identifies the recipients that the JWT is intended for (must include this authorization server)
/// - exp (expiration time): Identifies the expiration time on or after which the JWT MUST NOT be accepted
/// - jti (JWT ID): Optional but recommended for replay protection per RFC 7523 Section 5.2
///
/// The authorization server validates the JWT signature, claims, and ensures the issuer is trusted
/// before issuing an access token.
/// </remarks>
/// <param name="jwtValidator">Validates JWT assertions including signature verification and claims validation.</param>
/// <param name="issuerProvider">Provides comprehensive JWT Bearer functionality including trusted issuers, keys, and replay protection.</param>
/// <param name="requestInfoProvider">Provides information about the current HTTP request for audience validation.</param>
/// <param name="sessionIdGenerator">Generates unique session identifiers for authentication sessions.</param>
/// <param name="timeProvider">Provides access to the current time for session timestamps.</param>
/// <param name="logger">Logger for recording JWT Bearer grant validation events and errors.</param>
public class JwtBearerGrantHandler(
	IJsonWebTokenValidator jwtValidator,
	IJwtBearerIssuerProvider issuerProvider,
	IRequestInfoProvider requestInfoProvider,
	ISessionIdGenerator sessionIdGenerator,
	TimeProvider timeProvider,
	ILogger<JwtBearerGrantHandler> logger) : IAuthorizationGrantHandler
{
	/// <summary>
	/// Specifies the grant type that this handler supports, which is the JWT Bearer grant type.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported
	{
		get { yield return GrantTypes.JwtBearer; }
	}

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
	/// Asynchronously processes the token request using the JWT Bearer grant type.
	/// Validates the JWT assertion and, if valid, issues an access token.
	/// </summary>
	/// <param name="request">The token request containing the JWT assertion and requested scope.</param>
	/// <param name="clientInfo">Information about the authenticated client making the request.</param>
	/// <returns>
	/// A task that completes with either an authorized grant containing the user session and context,
	/// or an error indicating why the JWT assertion was rejected.
	/// </returns>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
		TokenRequest request,
		ClientInfo clientInfo)
	{
		return ValidateAssertionParameter(request, clientInfo)
			.BindAsync(assertion => ValidateJwtAsync(assertion, clientInfo))
			.BindAsync(jwt => ValidateSubjectAsync(jwt, clientInfo))
			.Bind(ctx => ValidateAlgorithm(ctx, clientInfo))
			.Bind(ctx => ValidateTokenType(ctx, clientInfo))
			.Bind(ctx => ValidateJwtAge(ctx, clientInfo))
			.BindAsync(ctx => ValidateReplayProtectionAsync(ctx, clientInfo))
			.Bind(ctx => ValidateScopes(ctx, request.Scope))
			.MapSuccessAsync(ctx => Task.FromResult(CreateAuthorizedGrant(ctx, request.Scope, clientInfo)));
	}

	/// <summary>
	/// Contains validated JWT data passed through the validation pipeline.
	/// </summary>
	private sealed record ValidationContext(JsonWebToken Jwt, string Subject, string Issuer, TrustedIssuer? TrustedIssuer);

	/// <summary>
	/// Validates that the assertion parameter is present and within size limits.
	/// </summary>
	private Result<string, OidcError> ValidateAssertionParameter(TokenRequest request, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;

		if (string.IsNullOrWhiteSpace(request.Assertion))
		{
			logger.LogWarning("JWT Bearer grant request missing required 'assertion' parameter from client {ClientId}",
				clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidGrant, "The 'assertion' parameter is required for JWT Bearer grant type");
		}

		if (request.Assertion.Length > options.MaxJwtSize)
		{
			logger.LogWarning("JWT assertion too large ({Length} chars, max {MaxSize}) from client {ClientId}",
				request.Assertion.Length, options.MaxJwtSize, clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidGrant,
				$"The JWT assertion exceeds maximum allowed size of {options.MaxJwtSize} characters");
		}

		return request.Assertion;
	}

	/// <summary>
	/// Validates the JWT signature, lifetime, issuer, and audience claims.
	/// </summary>
	private async Task<Result<JsonWebToken, OidcError>> ValidateJwtAsync(string assertion, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;

		var validationResult = await jwtValidator.ValidateAsync(
			assertion,
			new()
			{
				Options = ValidationOptions.ValidateLifetime |
				          ValidationOptions.ValidateIssuer |
				          ValidationOptions.ValidateAudience,
				ValidateIssuer = ValidateIssuer,
				ValidateAudience = ValidateAudience,
				ResolveIssuerSigningKeys = issuerProvider.GetSigningKeysAsync,
				ClockSkew = options.ClockSkew,
			});

		return validationResult.MapFailure(failure =>
		{
			var (error, errorDescription) = failure;

			logger.LogWarning(
				"JWT assertion validation failed for client {ClientId}: {ErrorCode} - {ErrorDescription}",
				clientInfo.ClientId, error, errorDescription);

			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion is invalid or has expired");
		});
	}

	/// <summary>
	/// Validates the subject claim is present and retrieves trusted issuer configuration.
	/// </summary>
	private async Task<Result<ValidationContext, OidcError>> ValidateSubjectAsync(JsonWebToken jwt, ClientInfo clientInfo)
	{
		var subject = jwt.Payload.Subject;
		if (string.IsNullOrWhiteSpace(subject))
		{
			logger.LogWarning("JWT assertion missing required 'sub' claim for client {ClientId}", clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion must contain a 'sub' (subject) claim");
		}

		var issuer = jwt.Payload.Issuer ?? "unknown";
		var trustedIssuer = await issuerProvider.GetTrustedIssuerAsync(issuer);

		return new ValidationContext(jwt, subject, issuer, trustedIssuer);
	}

	/// <summary>
	/// Validates that the JWT signing algorithm is in the allowed list.
	/// </summary>
	private Result<ValidationContext, OidcError> ValidateAlgorithm(ValidationContext ctx, ClientInfo clientInfo)
	{
		var allowedAlgorithms = ctx.TrustedIssuer?.AllowedAlgorithms ?? DefaultAllowedAlgorithms;
		var algorithm = ctx.Jwt.Header.Algorithm;

		if (allowedAlgorithms.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
			return ctx;

		logger.LogWarning("JWT assertion rejected: algorithm {Algorithm} not allowed for issuer {Issuer}, client {ClientId}",
			algorithm, ctx.Issuer, clientInfo.ClientId);

		return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion uses an unsupported signature algorithm");
	}

	/// <summary>
	/// Validates the JWT token type header against allowed types if configured.
	/// </summary>
	private Result<ValidationContext, OidcError> ValidateTokenType(ValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		if (options.AllowedTokenTypes is not { Length: > 0 } allowedTypes)
			return ctx;

		var tokenType = ctx.Jwt.Header.Type;
		if (allowedTypes.Contains(tokenType, StringComparer.OrdinalIgnoreCase))
			return ctx;

		logger.LogWarning(
			"JWT assertion rejected: token type '{TokenType}' not in allowed types [{AllowedTypes}], client {ClientId}, issuer {Issuer}",
			tokenType ?? "(none)", string.Join(", ", allowedTypes), clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has an unsupported token type");
	}

	/// <summary>
	/// Validates that the JWT is not too old based on MaxJwtAge configuration.
	/// </summary>
	private Result<ValidationContext, OidcError> ValidateJwtAge(ValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		if (options.MaxJwtAge is not { } maxAge)
			return ctx;

		var issuedAt = ctx.Jwt.Payload.IssuedAt;
		if (issuedAt == null)
		{
			logger.LogWarning(
				"JWT assertion rejected: missing 'iat' claim but MaxJwtAge is configured, client {ClientId}, issuer {Issuer}",
				clientInfo.ClientId, ctx.Issuer);

			return new OidcError(ErrorCodes.InvalidGrant,
				"The JWT assertion must contain an 'iat' (issued at) claim when age validation is enabled");
		}

		var now = timeProvider.GetUtcNow();
		var jwtAge = now - issuedAt.Value;

		if (jwtAge <= maxAge + options.ClockSkew)
			return ctx;

		logger.LogWarning(
			"JWT assertion rejected: JWT too old. Issued at {IssuedAt}, age {JwtAge}, max allowed {MaxAge}, client {ClientId}, issuer {Issuer}",
			issuedAt, jwtAge, maxAge, clientInfo.ClientId, ctx.Issuer);

		return new OidcError(ErrorCodes.InvalidGrant,
			"The JWT assertion is too old. Please use a freshly issued JWT.");
	}

	/// <summary>
	/// Validates that the JWT has not been used before (replay protection per RFC 7523 Section 5.2).
	/// </summary>
	private async Task<Result<ValidationContext, OidcError>> ValidateReplayProtectionAsync(ValidationContext ctx, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;
		if (!options.RequireJti)
			return ctx;

		var jti = ctx.Jwt.Payload.JwtId;
		if (string.IsNullOrWhiteSpace(jti))
		{
			logger.LogWarning("JWT assertion missing required 'jti' claim for client {ClientId}, issuer {Issuer}",
				clientInfo.ClientId, ctx.Issuer);
			return new OidcError(ErrorCodes.InvalidGrant,
				"The JWT assertion must contain a 'jti' (JWT ID) claim for replay protection");
		}

		if (await issuerProvider.IsReplayedAsync(jti))
		{
			logger.LogWarning(
				"SECURITY: JWT replay attack detected - JTI: {JwtId}, Client: {ClientId}, Issuer: {Issuer}, KeyId: {KeyId}, IP: {ClientIp}",
				jti, clientInfo.ClientId, ctx.Issuer, ctx.Jwt.Header.KeyId ?? "none", requestInfoProvider.RemoteIpAddress);
			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has already been used");
		}

		await issuerProvider.MarkAsUsedAsync(jti, ctx.Jwt.Payload.ExpiresAt);
		return ctx;
	}

	/// <summary>
	/// Validates that requested scopes are allowed for the issuer.
	/// </summary>
	private Result<ValidationContext, OidcError> ValidateScopes(ValidationContext ctx, string[]? scope)
	{
		if (ctx is not { TrustedIssuer.AllowedScopes: { Length: > 0 } allowedScopes} || scope is null)
			return ctx;

		var invalidScopes = scope.Except(allowedScopes).ToArray();
		if (invalidScopes.Length == 0)
			return ctx;

		logger.LogWarning("JWT Bearer grant rejected: scopes {InvalidScopes} not allowed for issuer {Issuer}",
			invalidScopes, ctx.Issuer);

		return new OidcError(
			ErrorCodes.InvalidScope,
			$"The following scopes are not allowed for this issuer: {string.Join(", ", invalidScopes)}");
	}

	/// <summary>
	/// Creates the authorized grant after successful validation.
	/// </summary>
	private AuthorizedGrant CreateAuthorizedGrant(ValidationContext ctx, string[] scope, ClientInfo clientInfo)
	{
		logger.LogInformation(
			"AUDIT: JWT Bearer grant SUCCESS - Client: {ClientId}, Subject: {Subject}, Issuer: {Issuer}, JTI: {JwtId}, KeyId: {KeyId}, IP: {ClientIp}",
			clientInfo.ClientId, ctx.Subject, ctx.Issuer, ctx.Jwt.Payload.JwtId ?? "none",
			ctx.Jwt.Header.KeyId ?? "none", requestInfoProvider.RemoteIpAddress);

		var context = new AuthorizationContext(clientInfo.ClientId, scope, null);

		var authSession = new AuthSession(
			Subject: ctx.Subject,
			SessionId: sessionIdGenerator.GenerateSessionId(),
			AuthenticationTime: timeProvider.GetUtcNow(),
			IdentityProvider: ctx.Issuer)
		{
			AffectedClientIds = { clientInfo.ClientId }
		};

		return new AuthorizedGrant(authSession, context);
	}

	/// <summary>
	/// Validates that the JWT issuer is from a trusted identity provider per RFC 7523 Section 3.
	/// </summary>
	/// <param name="issuer">The issuer claim from the JWT.</param>
	/// <returns>
	/// A task that completes with true if the issuer is trusted for JWT Bearer grants; otherwise, false.
	/// </returns>
	private async Task<bool> ValidateIssuer(string issuer)
	{
		var isTrusted = await issuerProvider.IsTrustedIssuerAsync(issuer);
		if (!isTrusted)
		{
			logger.LogWarning("JWT Bearer assertion rejected: issuer {Issuer} is not trusted", issuer);
		}
		return isTrusted;
	}

	/// <summary>
	/// Validates that the JWT audience includes this authorization server's token endpoint per RFC 7523 Section 3.
	/// The audience must match the token endpoint URI where the assertion is being presented.
	/// Uses URI normalization per RFC 3986 for proper comparison.
	/// </summary>
	/// <param name="audiences">The audience claims from the JWT.</param>
	/// <returns>
	/// A task that completes with true if the audience is valid; otherwise, false.
	/// </returns>
	private Task<bool> ValidateAudience(IEnumerable<string> audiences)
	{
		var options = issuerProvider.Options;

		if (!Uri.TryCreate(requestInfoProvider.RequestUri, UriKind.Absolute, out var tokenEndpoint))
			return Task.FromResult(false);

		var isValid = options.StrictAudienceValidation
			? ValidateStrict(audiences, tokenEndpoint)
			: ValidatePermissive(audiences, tokenEndpoint, requestInfoProvider.ApplicationUri);

		if (isValid)
			return Task.FromResult(true);

		if (options.StrictAudienceValidation)
		{
			logger.LogWarning(
				"JWT Bearer assertion rejected: audience validation failed. Expected {TokenEndpoint}, got {@Audiences}",
				tokenEndpoint,
				audiences);
		}
		else
		{
			logger.LogWarning(
				"JWT Bearer assertion rejected: audience validation failed. Expected {TokenEndpoint} or {ApplicationUri}, got {@Audiences}",
				tokenEndpoint,
				requestInfoProvider.ApplicationUri,
				audiences);
		}

		return Task.FromResult(false);
	}

	private static bool ValidateStrict(IEnumerable<string> audiences, Uri tokenEndpoint)
	{
		return audiences.Any(aud =>
			Uri.TryCreate(aud, UriKind.Absolute, out var audience) &&
			NormalizedUriEquals(audience, tokenEndpoint));
	}

	private static bool ValidatePermissive(IEnumerable<string> audiences, Uri tokenEndpoint, string applicationUri)
	{
		return Uri.TryCreate(applicationUri, UriKind.Absolute, out var appUri) &&
		       audiences.Any(aud =>
			       Uri.TryCreate(aud, UriKind.Absolute, out var audience) &&
			       (NormalizedUriEquals(audience, tokenEndpoint) ||
			        NormalizedUriEquals(audience, appUri)));
	}

	/// <summary>
	/// Compares two URIs using RFC 3986 normalization rules:
	/// scheme and host are case-insensitive, path is case-sensitive.
	/// </summary>
	private static bool NormalizedUriEquals(Uri uri1, Uri uri2)
		=> string.Equals(uri1.Scheme, uri2.Scheme, StringComparison.OrdinalIgnoreCase) &&
		   string.Equals(uri1.Host, uri2.Host, StringComparison.OrdinalIgnoreCase) &&
		   uri1.Port == uri2.Port &&
		   string.Equals(uri1.AbsolutePath.TrimEnd('/'), uri2.AbsolutePath.TrimEnd('/'), StringComparison.Ordinal);
}
