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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
/// - jti (JWT ID): Optional per RFC 7523 Section 3, which lets the authorization server keep
///   the set of used values and refuse a repeat
///
/// The authorization server validates the JWT signature, claims, and ensures the issuer is trusted
/// before issuing an access token.
/// </remarks>
/// <param name="jwtValidator">Validates JWT assertions including signature verification and claims validation.</param>
/// <param name="issuerProvider">Provides comprehensive JWT Bearer functionality including trusted issuers, keys, and replay protection.</param>
/// <param name="requestInfoProvider">Provides information about the current HTTP request for audience validation.</param>
/// <param name="sessionIdGenerator">Generates unique session identifiers for authentication sessions.</param>
/// <param name="timeProvider">Provides access to the current time for session timestamps.</param>
/// <param name="catalog">Tells an issuer this server serves, whose assertions are refused.</param>
/// <param name="logger">Logger for recording JWT Bearer grant validation events and errors.</param>
public partial class JwtBearerGrantHandler(
	ILogger<JwtBearerGrantHandler> logger,
	IJsonWebTokenValidator jwtValidator,
	IJwtBearerIssuerProvider issuerProvider,
	IRequestInfoProvider requestInfoProvider,
	ISessionIdGenerator sessionIdGenerator,
	TimeProvider timeProvider,
	ITenantCatalog catalog) : IAuthorizationGrantHandler
{
	private readonly JwtBearerAssertionPolicy _assertionPolicy =
		new(logger, issuerProvider, timeProvider);

	private readonly JwtBearerAssertionParameters _assertionParameters =
		new(logger, issuerProvider, requestInfoProvider, catalog);

	/// <summary>
	/// Specifies the grant type that this handler supports, which is the JWT Bearer grant type.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported
	{
		get { yield return GrantTypes.JwtBearer; }
	}

	/// <summary>
	/// Asynchronously processes the token request using the JWT Bearer grant type.
	/// Validates the JWT assertion and, if valid, issues an access token.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="request">The token request containing the JWT assertion and requested scope.</param>
	/// <param name="clientInfo">Information about the authenticated client making the request.</param>
	/// <returns>
	/// A task that completes with either an authorized grant containing the user session and context,
	/// or an error indicating why the JWT assertion was rejected.
	/// </returns>
	/// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
		TenantDefinition tenant,
		TokenRequest request,
		ClientInfo clientInfo,
		CancellationToken cancellationToken)
	{
		return ValidateAssertionParameter(request, clientInfo)
			.BindAsync(assertion => ValidateJwtAsync(tenant, assertion, clientInfo))
			.BindAsync(jwt => ValidateSubjectAsync(tenant, jwt, clientInfo))
			.Bind(ctx => _assertionPolicy.ValidateExpiration(ctx, clientInfo))
			.Bind(ctx => _assertionPolicy.ValidateAlgorithm(ctx, clientInfo))
			.Bind(ctx => _assertionPolicy.ValidateTokenType(ctx, clientInfo))
			.Bind(ctx => _assertionPolicy.ValidateJwtAge(tenant, ctx, clientInfo))
			.BindAsync(ctx => ValidateReplayProtectionAsync(ctx, clientInfo))
			.Bind(ctx => ValidateScopes(ctx, request.Scope))
			.MapSuccessAsync(ctx => Task.FromResult(CreateAuthorizedGrant(ctx, request.Scope, request.Resources, clientInfo)));
	}

	/// <summary>
	/// Validates that the assertion parameter is present and within size limits.
	/// </summary>
	private Result<string, OidcError> ValidateAssertionParameter(TokenRequest request, ClientInfo clientInfo)
	{
		var options = issuerProvider.Options;

		if (string.IsNullOrWhiteSpace(request.Assertion))
		{
			LogMissingAssertion(clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidGrant, "The 'assertion' parameter is required for JWT Bearer grant type");
		}

		if (request.Assertion.Length > options.MaxJwtSize)
		{
			LogAssertionTooLarge(request.Assertion.Length, options.MaxJwtSize, clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidGrant,
				$"The JWT assertion exceeds maximum allowed size of {options.MaxJwtSize} characters");
		}

		return request.Assertion;
	}

	/// <summary>
	/// Validates the JWT signature, lifetime, issuer, and audience claims.
	/// </summary>
	private async Task<Result<JsonWebToken, OidcError>> ValidateJwtAsync(TenantDefinition tenant, [Credential] string assertion, ClientInfo clientInfo)
	{
		var validationResult = await jwtValidator.ValidateAsync(
			assertion,
			_assertionParameters.For(tenant, _assertionPolicy.ResolveClockSkew(tenant, clientInfo)));

		return validationResult.MapFailure(failure =>
		{
			var (error, errorDescription) = failure;

			LogValidationFailed(clientInfo.ClientId, error, errorDescription);

			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion is invalid or has expired");
		});
	}

	/// <summary>
	/// Validates the subject claim is present and retrieves trusted issuer configuration.
	/// </summary>
	private async Task<Result<JwtBearerValidationContext, OidcError>> ValidateSubjectAsync(
		TenantDefinition tenant, JsonWebToken jwt, ClientInfo clientInfo)
	{
		var subject = jwt.Payload.Subject;
		if (string.IsNullOrWhiteSpace(subject))
		{
			LogMissingSubject(clientInfo.ClientId);
			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion must contain a 'sub' (subject) claim");
		}

		var issuer = jwt.Payload.Issuer ?? "unknown";
		var trustedIssuer = await issuerProvider.GetTrustedIssuerAsync(tenant, issuer);

		return new JwtBearerValidationContext(jwt, subject, issuer, trustedIssuer);
	}

	/// <summary>
	/// Validates that the JWT has not been used before (replay protection per RFC 7523 Section 3).
	/// </summary>
	private async Task<Result<JwtBearerValidationContext, OidcError>> ValidateReplayProtectionAsync(
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
		// the read-then-write race.
		if (await issuerProvider.IsReplayedAsync(jti, ctx.ExpiresAt))
		{
			LogReplayDetected(jti, clientInfo.ClientId, ctx.Issuer, ctx.Jwt.Header.KeyId ?? "none", requestInfoProvider.RemoteIpAddress);
			return new OidcError(ErrorCodes.InvalidGrant, "The JWT assertion has already been used");
		}

		return ctx;
	}

	/// <summary>
	/// Validates that requested scopes are allowed for the issuer.
	/// </summary>
	private Result<JwtBearerValidationContext, OidcError> ValidateScopes(
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
	/// Creates the authorized grant after successful validation.
	/// </summary>
	private AuthorizedGrant CreateAuthorizedGrant(
		JwtBearerValidationContext ctx, string[] scope, Uri[]? resources, ClientInfo clientInfo)
	{
		LogGrantSucceeded(
			clientInfo.ClientId, ctx.Subject, ctx.Issuer, ctx.Jwt.Payload.JwtId ?? "none",
			ctx.Jwt.Header.KeyId ?? "none", requestInfoProvider.RemoteIpAddress);

		return JwtBearerGrants.Of(
			ctx,
			clientInfo.ClientId,
			scope,
			resources,
			sessionIdGenerator.GenerateSessionId(),
			timeProvider.GetUtcNow());
	}
}
