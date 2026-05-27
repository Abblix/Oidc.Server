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
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// <see cref="IAuthorizationGrantHandler"/> for RFC 8693 Token Exchange
/// (<c>grant_type=urn:ietf:params:oauth:grant-type:token-exchange</c>).
/// </summary>
/// <remarks>
/// Per-format subject-token validation is delegated to keyed <see cref="ISubjectTokenResolver"/>
/// implementations: <see cref="JwtSubjectTokenResolver"/> for the three JWT-based type URIs
/// (<c>access_token</c>, <c>id_token</c>, <c>jwt</c>) and
/// <see cref="RefreshTokenSubjectTokenResolver"/> for refresh tokens. Lookup that returns no
/// resolver for the requested key yields <c>invalid_request</c> -- the library never silently
/// accepts an unknown <c>subject_token_type</c>. Hosts may register additional resolvers for
/// formats this library does not handle natively.
/// <para>
/// Supports both RFC 8693 §4.1 modes: impersonation (no <c>actor_token</c>; the issued token's
/// <c>sub</c> equals the subject_token's subject, no <c>act</c> claim) and delegation
/// (<c>actor_token</c> provided; the issued token's <c>sub</c> still equals the subject's
/// subject, and the <c>act</c> claim names the actor. When the subject_token itself already
/// carries an <c>act</c> chain, the new actor is layered on top -- the previous chain becomes
/// the new actor's nested <c>act.act</c>).
/// </para>
/// </remarks>
public class TokenExchangeGrantHandler(
    IParameterValidator parameterValidator,
    IServiceProvider serviceProvider,
    ISessionIdGenerator sessionIdGenerator,
    TimeProvider timeProvider) : IAuthorizationGrantHandler
{
    /// <inheritdoc/>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.TokenExchange; }
    }

    /// <inheritdoc/>
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        var pre = ValidateRequiredParameters(request)
            .Bind(req => ValidateSubjectTokenTypeAllowlist(req, clientInfo))
            .Bind(ValidateActorTokenPair);
        if (!pre.TryGetSuccess(out _))
            return pre.GetFailure();

        var subjectResult = await ResolveTokenAsync(request.SubjectTokenType!, request.SubjectToken!);
        if (!subjectResult.TryGetSuccess(out var subject))
            return subjectResult.GetFailure();

        SubjectTokenContext? actor = null;
        if (request.ActorToken is { Length: > 0 } actorToken)
        {
            var actorResult = await ResolveTokenAsync(request.ActorTokenType!, actorToken);
            if (!actorResult.TryGetSuccess(out actor))
                return new OidcError(ErrorCodes.InvalidRequest, $"actor_token: {actorResult.GetFailure().ErrorDescription}");
        }

        return BuildAuthorizedGrant(subject, actor, request, clientInfo);
    }

    private Result<TokenRequest, OidcError> ValidateRequiredParameters(TokenRequest request)
    {
        parameterValidator.Required(request.SubjectToken, nameof(request.SubjectToken));
        parameterValidator.Required(request.SubjectTokenType, nameof(request.SubjectTokenType));
        return request;
    }

    private static Result<TokenRequest, OidcError> ValidateSubjectTokenTypeAllowlist(
        TokenRequest request, ClientInfo clientInfo)
    {
        // Tri-state semantics (mirrors ClientInfo.AuthorizationDetailsTypes):
        //  null         -> no per-client constraint (library-wide resolver registry decides)
        //  empty array  -> deny-all (this client cannot use Token Exchange at all)
        //  non-empty    -> allowlist of accepted subject_token_type URIs
        var allowlist = clientInfo.TokenExchangeAllowedSubjectTokenTypes;
        if (allowlist is { Length: 0 })
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Client is not permitted to use the Token Exchange grant.");
        }

        if (allowlist is { Length: > 0 }
            && !allowlist.Contains(request.SubjectTokenType!, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token_type '{request.SubjectTokenType}' is not in the client's allowlist.");
        }

        return request;
    }

    /// <summary>
    /// RFC 8693 §2.1: <c>actor_token</c> and <c>actor_token_type</c> are mutually required when
    /// either is present -- a request that supplies one without the other is malformed.
    /// </summary>
    private static Result<TokenRequest, OidcError> ValidateActorTokenPair(TokenRequest request)
    {
        var hasToken = !string.IsNullOrEmpty(request.ActorToken);
        var hasType = !string.IsNullOrEmpty(request.ActorTokenType);
        if (hasToken != hasType)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "actor_token and actor_token_type must be supplied together.");
        }
        return request;
    }

    private async Task<Result<SubjectTokenContext, OidcError>> ResolveTokenAsync(string tokenType, string tokenValue)
    {
        var resolver = serviceProvider.GetKeyedService<ISubjectTokenResolver>(tokenType);
        if (resolver is null)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"token_type '{tokenType}' is not supported.");
        }

        return await resolver.ResolveAsync(tokenValue, default);
    }

    private AuthorizedGrant BuildAuthorizedGrant(
        SubjectTokenContext subject,
        SubjectTokenContext? actor,
        TokenRequest request,
        ClientInfo clientInfo)
    {
        // RFC 8693 §4.1: issued token's subject is always the subject_token's subject (impersonation
        // and delegation alike). Scope: when the client supplies scope in the request use that,
        // otherwise fall back to the subject_token's scope. Resource servers downstream of
        // narrow-at-exchange see only the scopes the client asked for.
        var scope = request.Scope is { Length: > 0 } ? request.Scope : subject.Scope ?? [];

        // Delegation act chain (RFC 8693 §4.1): when an actor_token was supplied, the new actor's
        // act object names the actor's subject; any prior act chain inherited from the
        // subject_token becomes the new actor's nested act.act, preserving the full delegation
        // path. Impersonation = no actor_token = no act emission.
        JsonObject? actorClaim = null;
        if (actor is not null)
        {
            actorClaim = new JsonObject { [IanaClaimTypes.Sub] = actor.Subject };
            if (subject.Act is not null)
            {
                actorClaim[IanaClaimTypes.Act] = subject.Act.DeepClone();
            }
        }

        var authContext = new AuthorizationContext(clientInfo.ClientId, scope, null)
        {
            AuthorizationDetails = subject.AuthorizationDetails,
            Actor = actorClaim,
        };

        var authSession = new AuthSession(
            Subject: subject.Subject,
            SessionId: sessionIdGenerator.GenerateSessionId(),
            AuthenticationTime: timeProvider.GetUtcNow(),
            IdentityProvider: subject.Issuer ?? "self")
        {
            AffectedClientIds = { clientInfo.ClientId },
        };

        return new AuthorizedGrant(authSession, authContext);
    }
}
