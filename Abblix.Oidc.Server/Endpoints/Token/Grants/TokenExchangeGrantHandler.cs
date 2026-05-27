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
        // Pre-flight: required params, per-client allowlist for BOTH subject and actor types
        // (C3 symmetry), actor pair completeness, requested_token_type sanity.
        ValidateRequiredParameters(request);

        if (ValidateTokenTypeAllowlist(request.SubjectTokenType!, clientInfo, "subject_token_type") is { } subjectTypeError)
            return subjectTypeError;

        if (ValidateActorTokenPair(request) is { } actorPairError)
            return actorPairError;

        if (request.ActorTokenType is { Length: > 0 } actorType
            && ValidateTokenTypeAllowlist(actorType, clientInfo, "actor_token_type") is { } actorTypeError)
            return actorTypeError;

        if (ValidateRequestedTokenType(request) is { } requestedTokenTypeError)
            return requestedTokenTypeError;

        var subjectResult = await ResolveTokenAsync(request.SubjectTokenType!, request.SubjectToken!);
        if (!subjectResult.TryGetSuccess(out var subject))
            return subjectResult.GetFailure();

        // S1 / S3: confused-deputy + typ-confusion guards on the resolved subject.
        if (ValidateSubjectTokenOriginAndType(subject, request.SubjectTokenType!, clientInfo) is { } subjectGateError)
            return subjectGateError;

        // S1-second: forwarded authorization_details must be allowed for the REQUESTING client,
        // not just for the subject_token's original client.
        if (ValidateForwardedAuthorizationDetails(subject, clientInfo) is { } adError)
            return adError;

        SubjectTokenContext? actor = null;
        if (request.ActorToken is { Length: > 0 } actorToken)
        {
            var actorResult = await ResolveTokenAsync(request.ActorTokenType!, actorToken);
            if (!actorResult.TryGetSuccess(out actor))
                return new OidcError(ErrorCodes.InvalidRequest, $"actor_token: {actorResult.GetFailure().ErrorDescription}");

            if (ValidateSubjectTokenOriginAndType(actor, request.ActorTokenType!, clientInfo) is { } actorGateError)
                return new OidcError(ErrorCodes.InvalidRequest, $"actor_token: {actorGateError.ErrorDescription}");
        }

        return BuildAuthorizedGrant(subject, actor, request, clientInfo);
    }

    private void ValidateRequiredParameters(TokenRequest request)
    {
        parameterValidator.Required(request.SubjectToken, nameof(request.SubjectToken));
        parameterValidator.Required(request.SubjectTokenType, nameof(request.SubjectTokenType));
    }

    /// <summary>
    /// Per-client allowlist gate, reusable for both <c>subject_token_type</c> and
    /// <c>actor_token_type</c> (C3 symmetry decision: a client opted in to exchanging type X
    /// as subject is implicitly trusted with type X as actor).
    /// Returns the failure (when present) or <c>null</c> when the check passes.
    /// Tri-state semantics (mirrors ClientInfo.AuthorizationDetailsTypes):
    ///   null         -> no per-client constraint (library-wide resolver registry decides)
    ///   empty array  -> deny-all (this client cannot use Token Exchange at all)
    ///   non-empty    -> allowlist of accepted token-type URIs
    /// </summary>
    private static OidcError? ValidateTokenTypeAllowlist(
        string tokenTypeUri, ClientInfo clientInfo, string fieldName)
    {
        var allowlist = clientInfo.TokenExchangeAllowedSubjectTokenTypes;
        if (allowlist is { Length: 0 })
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Client is not permitted to use the Token Exchange grant.");
        }

        // Tri-state: null = no per-client constraint -- skip the membership check entirely.
        // Without this guard the null-allowlist passthrough case NREs at .Contains() below.
        if (allowlist is { Length: > 0 }
            && !allowlist.Contains(tokenTypeUri, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"{fieldName} '{tokenTypeUri}' is not in the client's allow list.");
        }

        return null;
    }

    /// <summary>
    /// RFC 8693 §2.1: <c>actor_token</c> and <c>actor_token_type</c> are mutually required when
    /// either is present -- a request that supplies one without the other is malformed.
    /// </summary>
    private static OidcError? ValidateActorTokenPair(TokenRequest request)
    {
        var hasToken = !string.IsNullOrEmpty(request.ActorToken);
        var hasType = !string.IsNullOrEmpty(request.ActorTokenType);
        if (hasToken != hasType)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "actor_token and actor_token_type must be supplied together.");
        }
        return null;
    }

    /// <summary>
    /// S2 (PR #135 review): currently this slice issues only an access_token. Clients asking for
    /// id_token / refresh_token / jwt are rejected loudly rather than silently downgraded --
    /// otherwise the client assumes it got what it asked for and breaks downstream.
    /// </summary>
    private static OidcError? ValidateRequestedTokenType(TokenRequest request)
    {
        if (request.RequestedTokenType is { Length: > 0 } requested
            && requested != TokenExchangeTokenTypes.AccessToken)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"requested_token_type '{requested}' is not supported (only access_token issued).");
        }
        return null;
    }

    /// <summary>
    /// S1 + S3 (PR #135 review): the subject_token must have been issued to the requesting client
    /// (confused-deputy guard; opt-out via <see cref="ClientInfo.AllowCrossClientSubjectTokenExchange"/>
    /// for broker scenarios), and -- for JWT-based URIs -- the JWT typ header must match the URI
    /// it was presented under (cross-type confusion guard, e.g. id+jwt as access_token).
    /// </summary>
    private static OidcError? ValidateSubjectTokenOriginAndType(
        SubjectTokenContext token, string requestedTypeUri, ClientInfo clientInfo)
    {
        if (token.OriginalClientId is { Length: > 0 } originalClient
            && !string.Equals(originalClient, clientInfo.ClientId, StringComparison.Ordinal)
            && !clientInfo.AllowCrossClientSubjectTokenExchange)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "subject_token was issued to a different client than the one presenting it.");
        }

        // typ header expected per URI (JWT-based subject types only):
        //   access_token  -> at+jwt
        //   id_token      -> id+jwt
        //   jwt           -> any typ acceptable (generic JWT URI)
        // Resolvers for non-JWT formats leave JwtTokenType null; this check is a no-op for them.
        var expectedTyp = requestedTypeUri switch
        {
            TokenExchangeTokenTypes.AccessToken => JwtTypes.AccessToken,
            TokenExchangeTokenTypes.IdToken => JwtTypes.IdToken,
            TokenExchangeTokenTypes.RefreshToken => JwtTypes.RefreshToken,
            _ => null,  // jwt (or non-JWT formats) -- no typ-header expectation
        };
        if (expectedTyp is not null
            && token.JwtTokenType is { Length: > 0 } actualTyp
            && !string.Equals(actualTyp, expectedTyp, StringComparison.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token has typ '{actualTyp}' but was presented under '{requestedTypeUri}' (expected typ '{expectedTyp}').");
        }

        return null;
    }

    /// <summary>
    /// S1-second (PR #135 review): the AD entries forwarded from the subject_token must be
    /// allowed for the REQUESTING client per its own <see cref="ClientInfo.AuthorizationDetailsTypes"/>
    /// allowlist. Without this check, leaked tokens carrying expensive grants escalate
    /// silently across clients.
    /// </summary>
    private static OidcError? ValidateForwardedAuthorizationDetails(
        SubjectTokenContext subject, ClientInfo clientInfo)
    {
        if (subject.AuthorizationDetails is not { Count: > 0 } forwarded)
            return null;

        var allowlist = clientInfo.AuthorizationDetailsTypes;
        // Null allowlist = no per-client constraint (consistent with RAR semantics).
        if (allowlist is null)
            return null;

        if (allowlist.Length == 0)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Requesting client is not permitted to receive forwarded authorization_details.");
        }

        var allowed = new HashSet<string>(allowlist, StringComparer.Ordinal);
        foreach (var entry in forwarded)
        {
            if (entry is JsonObject obj
                && obj["type"]?.GetValue<string>() is { Length: > 0 } type
                && !allowed.Contains(type))
            {
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    $"subject_token's authorization_details type '{type}' is not in the requesting client's allow list.");
            }
        }
        return null;
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
            // S2 (PR #135 review): propagate the requested resource(s) (RFC 8707) and audience(s)
            // (RFC 8693 §2.1) into the issued token's claims rather than silently dropping them.
            Resources = request.Resources is { Length: > 0 } ? request.Resources : null,
            Audiences = request.Audiences is { Length: > 0 } ? request.Audiences : null,
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
