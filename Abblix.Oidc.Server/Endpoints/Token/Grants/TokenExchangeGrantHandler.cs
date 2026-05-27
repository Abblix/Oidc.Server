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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for RFC 8693 Token Exchange
/// (<c>grant_type=urn:ietf:params:oauth:grant-type:token-exchange</c>).
/// </summary>
/// <remarks>
/// Slice 1 scope: JWT-based subject tokens (<c>urn:ietf:params:oauth:token-type:access_token</c>,
/// <c>:id_token</c>, <c>:jwt</c>) -- the AS treats them as own-issued JWTs and validates signature,
/// lifetime, and structure via <see cref="IAuthServiceJwtValidator"/>. Impersonation mode only:
/// the issued token carries the subject_token's <c>sub</c>, <c>scope</c>, and <c>authorization_details</c>
/// claims forward without an <c>act</c> chain. Per-client allowlist of accepted subject token types
/// is enforced via <see cref="ClientInfo.TokenExchangeAllowedSubjectTokenTypes"/> with the documented
/// tri-state semantics (null = no constraint, empty = forbid, non-empty = allowlist).
/// <para>
/// Subsequent slices add opaque (refresh-token) subject tokens (#143 slice 2), <c>actor_token</c> +
/// delegation <c>act</c> chain (#143 slice 3), and discovery / DCR metadata (#143 slice 4).
/// </para>
/// </remarks>
public class TokenExchangeGrantHandler(
    IParameterValidator parameterValidator,
    IAuthServiceJwtValidator jwtValidator,
    ISessionIdGenerator sessionIdGenerator,
    TimeProvider timeProvider) : IAuthorizationGrantHandler
{
    /// <summary>The grant type this handler implements.</summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.TokenExchange; }
    }

    /// <summary>
    /// Subject token types this slice can validate. Opaque-token formats land in slice 2 via
    /// <c>ISubjectTokenResolver</c> keyed dispatch.
    /// </summary>
    private static readonly string[] SupportedSubjectTokenTypes =
    [
        TokenExchangeTokenTypes.AccessToken,
        TokenExchangeTokenTypes.IdToken,
        TokenExchangeTokenTypes.Jwt,
    ];

    /// <inheritdoc/>
    public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        return ValidateRequiredParameters(request)
            .Bind(req => ValidateSubjectTokenType(req, clientInfo))
            .Bind(RejectActorTokenForNow)
            .BindAsync(req => ValidateSubjectJwtAsync(req.SubjectToken!))
            .Bind(RequireSubjectClaim)
            .MapSuccessAsync(ctx => Task.FromResult(BuildAuthorizedGrant(ctx, request, clientInfo)));
    }

    private sealed record SubjectContext(JsonWebToken Jwt, string Subject);

    private Result<TokenRequest, OidcError> ValidateRequiredParameters(TokenRequest request)
    {
        parameterValidator.Required(request.SubjectToken, nameof(request.SubjectToken));
        parameterValidator.Required(request.SubjectTokenType, nameof(request.SubjectTokenType));
        return request;
    }

    private static Result<TokenRequest, OidcError> ValidateSubjectTokenType(TokenRequest request, ClientInfo clientInfo)
    {
        var requested = request.SubjectTokenType!;

        if (!SupportedSubjectTokenTypes.Contains(requested, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token_type '{requested}' is not supported (this slice accepts JWT-based subject tokens only).");
        }

        var allowlist = clientInfo.TokenExchangeAllowedSubjectTokenTypes;
        if (allowlist is { Length: 0 })
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Client is not permitted to use the Token Exchange grant.");
        }

        if (allowlist is { Length: > 0 } && !allowlist.Contains(requested, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token_type '{requested}' is not in the client's allowlist.");
        }

        return request;
    }

    /// <summary>
    /// Delegation via <c>actor_token</c> lands in #143 slice 3. In slice 1 the AS only supports
    /// impersonation; a request that carries <c>actor_token</c> is rejected loudly rather than
    /// silently downgraded to impersonation -- silent downgrade would emit a token that does not
    /// reflect the requested delegation, a serious authorization surprise.
    /// </summary>
    private static Result<TokenRequest, OidcError> RejectActorTokenForNow(TokenRequest request)
    {
        if (request.ActorToken is { Length: > 0 } || request.ActorTokenType is { Length: > 0 })
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Delegation via actor_token is not yet supported (impersonation only).");
        }
        return request;
    }

    private async Task<Result<JsonWebToken, OidcError>> ValidateSubjectJwtAsync(string subjectToken)
    {
        var validation = await jwtValidator.ValidateAsync(subjectToken);
        return validation.MapFailure(error =>
            new OidcError(ErrorCodes.InvalidRequest, "The subject_token is invalid or has expired."));
    }

    private static Result<SubjectContext, OidcError> RequireSubjectClaim(JsonWebToken jwt)
    {
        var subject = jwt.Payload.Subject;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "subject_token is missing the required 'sub' claim.");
        }
        return new SubjectContext(jwt, subject);
    }

    private AuthorizedGrant BuildAuthorizedGrant(
        SubjectContext ctx,
        TokenRequest request,
        ClientInfo clientInfo)
    {
        // RFC 8693 §4.1 impersonation: the issued token's subject equals the subject_token's
        // subject and no `act` chain is added. Scope and authorization_details flow from the
        // subject_token (or, when present in the request, the narrowed values intersected
        // with what the subject_token already carried -- enforcement deferred to slice 5).
        var scope = request.Scope is { Length: > 0 }
            ? request.Scope
            : ctx.Jwt.Payload.Scope.ToArray();

        // Deep-clone the raw JsonArray to detach it from the subject_token's payload before
        // it is forwarded into the new AuthorizationContext (and onward into a fresh JWT).
        // Without the clone the issued token would share JsonNode parent ownership with the
        // subject_token's payload, which System.Text.Json rejects on the next serialisation.
        var authorizationDetailsRaw =
            ctx.Jwt.Payload.Json[IanaClaimTypes.AuthorizationDetails] is JsonArray ad
                ? (JsonArray?)ad.DeepClone()
                : null;

        var authContext = new AuthorizationContext(clientInfo.ClientId, scope, null)
        {
            AuthorizationDetails = authorizationDetailsRaw,
        };

        var authSession = new AuthSession(
            Subject: ctx.Subject,
            SessionId: sessionIdGenerator.GenerateSessionId(),
            AuthenticationTime: timeProvider.GetUtcNow(),
            IdentityProvider: ctx.Jwt.Payload.Issuer ?? "self")
        {
            AffectedClientIds = { clientInfo.ClientId },
        };

        return new AuthorizedGrant(authSession, authContext);
    }
}
