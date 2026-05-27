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
/// Currently impersonation mode only -- <c>actor_token</c> is rejected loudly to avoid silently
/// downgrading a requested delegation to impersonation. Delegation + <c>act</c> claim chain
/// lands in #143 slice 3.
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
    public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        return ValidateRequiredParameters(request)
            .Bind(req => ValidateSubjectTokenTypeAllowlist(req, clientInfo))
            .Bind(RejectActorTokenForNow)
            .BindAsync(req => ResolveSubjectAsync(req))
            .MapSuccessAsync(ctx => Task.FromResult(BuildAuthorizedGrant(ctx, request, clientInfo)));
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

    private async Task<Result<SubjectTokenContext, OidcError>> ResolveSubjectAsync(TokenRequest request)
    {
        var resolver = serviceProvider.GetKeyedService<ISubjectTokenResolver>(request.SubjectTokenType!);
        if (resolver is null)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token_type '{request.SubjectTokenType}' is not supported.");
        }

        return await resolver.ResolveAsync(request.SubjectToken!, default);
    }

    private AuthorizedGrant BuildAuthorizedGrant(
        SubjectTokenContext subject,
        TokenRequest request,
        ClientInfo clientInfo)
    {
        // RFC 8693 §4.1 impersonation: issued token's subject equals the subject_token's
        // subject; no act chain. Scope: when the client supplies scope in the request use that,
        // otherwise fall back to the subject_token's scope. Resource servers downstream of
        // narrow-at-exchange will see only the scopes the client asked for.
        var scope = request.Scope is { Length: > 0 } ? request.Scope : subject.Scope ?? [];

        var authContext = new AuthorizationContext(clientInfo.ClientId, scope, null)
        {
            AuthorizationDetails = subject.AuthorizationDetailsRaw,
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
