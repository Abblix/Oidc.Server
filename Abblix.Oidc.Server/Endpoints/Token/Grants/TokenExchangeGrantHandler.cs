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
/// Authorization is structured as a monadic <c>Bind</c>-chain on
/// <see cref="Result{TSuccess,TFailure}"/>, mirroring <see cref="JwtBearerGrantHandler"/>: each
/// step returns either an enriched <see cref="ValidationContext"/> or an <see cref="OidcError"/>;
/// the chain short-circuits at the first failure. Subject-token resolution sits in the middle
/// of the chain, so post-resolve guards (cross-client origin, typ-confusion, forwarded AD
/// allowlist) read the resolved <see cref="SubjectTokenContext"/> directly from the context.
/// </para>
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
    public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
        TokenRequest request,
        ClientInfo clientInfo)
    {
        Result<ValidationContext, OidcError> initial = new ValidationContext(request, clientInfo);

        return initial
            .Bind(ValidateRequiredParameters)
            .Bind(ValidateSubjectTokenType)
            .Bind(ValidateActorTokenPair)
            .Bind(ValidateActorTokenType)
            .Bind(ValidateRequestedTokenType)
            .BindAsync(ResolveSubjectTokenAsync)
            .Bind(ValidateSubjectTokenOriginAndType)
            .Bind(ValidateForwardedAuthorizationDetails)
            .BindAsync(ResolveActorTokenAsync)
            .Bind(ValidateActorTokenOriginAndType)
            .Bind(ValidateAudiences)
            .MapSuccessAsync(ctx => Task.FromResult(BuildAuthorizedGrant(ctx)));
    }

    /// <summary>
    /// Accumulator threaded through the <c>Bind</c>-chain. <see cref="Subject"/> is populated by
    /// <see cref="ResolveSubjectTokenAsync"/>; <see cref="Actor"/> is populated by
    /// <see cref="ResolveActorTokenAsync"/> only when the request supplied <c>actor_token</c>.
    /// </summary>
    private sealed record ValidationContext(
        TokenRequest Request,
        ClientInfo ClientInfo,
        SubjectTokenContext? Subject = null,
        SubjectTokenContext? Actor = null);

    /// <summary>
    /// RFC 8693 §2.1: <c>subject_token</c> and <c>subject_token_type</c> are REQUIRED. A missing one
    /// is the caller's protocol error (<c>invalid_request</c> per RFC 6749 §5.2), not a server
    /// fault — the previous throw-on-access surfaced it as HTTP 500.
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateRequiredParameters(ValidationContext ctx)
    {
        if (!ctx.Request.SubjectToken.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.SubjectToken);
        }

        if (!ctx.Request.SubjectTokenType.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.SubjectTokenType);
        }

        return ctx;
    }

    /// <summary>
    /// Checks the <c>subject_token_type</c> against the client's tri-state per-client allowlist.
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateSubjectTokenType(ValidationContext ctx)
    {
        if (CheckTokenTypeAllowlist(
                ctx.Request.SubjectTokenType,
                ctx.ClientInfo,
                TokenRequest.Parameters.SubjectTokenType) is { } error)
        {
            return error;
        }

        return ctx;
    }

    /// <summary>
    /// RFC 8693 §2.1: <c>actor_token</c> and <c>actor_token_type</c> are mutually required when
    /// either is present -- a request that supplies one without the other is malformed.
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateActorTokenPair(ValidationContext ctx)
    {
        var hasToken = !string.IsNullOrEmpty(ctx.Request.ActorToken);
        var hasType = !string.IsNullOrEmpty(ctx.Request.ActorTokenType);
        if (hasToken != hasType)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "actor_token and actor_token_type must be supplied together.");
        }

        return ctx;
    }

    /// <summary>
    /// Same allowlist check as <see cref="ValidateSubjectTokenType"/> applied to
    /// <c>actor_token_type</c> (C3 symmetry: a client opted in to exchanging type X as subject
    /// is implicitly trusted with type X as actor).
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateActorTokenType(ValidationContext ctx)
    {
        if (CheckTokenTypeAllowlist(
                ctx.Request.ActorTokenType,
                ctx.ClientInfo,
                TokenRequest.Parameters.ActorTokenType) is { } error)
        {
            return error;
        }

        return ctx;
    }

    /// <summary>
    /// S2 (PR #135 review): this slice issues only access_token; clients asking for id_token /
    /// refresh_token / jwt are rejected loudly rather than silently downgraded.
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateRequestedTokenType(ValidationContext ctx)
    {
        var requested = ctx.Request.RequestedTokenType;
        if (requested is { Length: > 0 } && requested != TokenExchangeTokenTypes.AccessToken)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"requested_token_type '{requested}' is not supported (only access_token issued).");
        }

        return ctx;
    }

    /// <summary>
    /// Per-client allowlist gate, reusable for both <c>subject_token_type</c> and
    /// <c>actor_token_type</c>.
    /// Tri-state semantics (mirrors <see cref="ClientInfo.AuthorizationDetailsTypes"/>):
    ///   null         -> no per-client constraint (library-wide resolver registry decides)
    ///   empty array  -> deny-all (this client cannot use Token Exchange at all)
    ///   non-empty    -> allowlist of accepted token-type URIs
    /// </summary>
    private static OidcError? CheckTokenTypeAllowlist(
        string? tokenTypeUri,
        ClientInfo clientInfo,
        string fieldName)
    {
        if (string.IsNullOrEmpty(tokenTypeUri))
            return null;

        // Tri-state: null = no per-client constraint -- skip membership check entirely so the
        // null-allowlist passthrough case does not NRE at .Contains().
        switch (clientInfo.TokenExchangeAllowedSubjectTokenTypes)
        {
            case { Length: 0 }:
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "Client is not permitted to use the Token Exchange grant.");

            case { Length: > 0 } allowlist when !allowlist.Contains(tokenTypeUri, StringComparer.Ordinal):
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    $"{fieldName} '{tokenTypeUri}' is not in the client's allow list.");
        }

        return null;
    }

    /// <summary>
    /// Resolves the <c>subject_token</c> through the keyed-DI resolver matching its declared
    /// type URI and stores the resolved <see cref="SubjectTokenContext"/> on the chain context.
    /// </summary>
    private async Task<Result<ValidationContext, OidcError>> ResolveSubjectTokenAsync(ValidationContext ctx)
    {
        var subjectToken = ctx.Request.SubjectToken.NotNull(TokenRequest.Parameters.SubjectToken);
        var result = await ResolveTokenAsync(ctx.Request.SubjectTokenType, subjectToken, CancellationToken.None);
        return result.MapSuccess(subject => ctx with { Subject = subject });
    }

    /// <summary>
    /// S1 + S3 (PR #135 review): the subject_token must have been issued to the requesting client
    /// (confused-deputy guard; opt-out via <see cref="ClientInfo.AllowCrossClientSubjectTokenExchange"/>
    /// for broker scenarios), and -- for JWT-based URIs -- the JWT typ header must match the URI
    /// it was presented under (cross-type confusion guard, e.g. id+jwt as access_token).
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateSubjectTokenOriginAndType(ValidationContext ctx)
    {
        if (CheckTokenOriginAndType(
                ctx.Subject.NotNull(nameof(ctx.Subject)),
                ctx.Request.SubjectTokenType,
                ctx.ClientInfo) is { } error)
        {
            return error;
        }

        return ctx;
    }

    /// <summary>
    /// S1-second (PR #135 review): AD entries forwarded from the subject_token must be allowed
    /// for the REQUESTING client per its own <see cref="ClientInfo.AuthorizationDetailsTypes"/>
    /// allowlist. Without this check, leaked tokens carrying expensive grants escalate silently
    /// across clients.
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateForwardedAuthorizationDetails(ValidationContext ctx)
    {
        var subject = ctx.Subject.NotNull(nameof(ctx.Subject));
        if (subject.AuthorizationDetails is not { Count: > 0 } forwarded)
            return ctx;

        var allowlist = ctx.ClientInfo.AuthorizationDetailsTypes;
        // Null allowlist = no per-client constraint (consistent with RAR semantics).
        if (allowlist is null)
            return ctx;

        if (allowlist.Length == 0)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Requesting client is not permitted to receive forwarded authorization_details.");
        }

        var allowed = new HashSet<string>(allowlist, StringComparer.Ordinal);
        foreach (var entry in forwarded)
        {
            if (entry is JsonObject obj &&
                obj["type"]?.GetValue<string>() is { Length: > 0 } type &&
                !allowed.Contains(type))
            {
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    $"subject_token's authorization_details type '{type}' is not in the requesting client's allow list.");
            }
        }

        return ctx;
    }

    /// <summary>
    /// Resolves the optional <c>actor_token</c>. Passthrough (no enrichment) when the request
    /// has no actor; failures are wrapped with an <c>actor_token:</c> prefix so the wire-level
    /// error pinpoints which token was rejected.
    /// </summary>
    private async Task<Result<ValidationContext, OidcError>> ResolveActorTokenAsync(ValidationContext ctx)
    {
        if (ctx.Request.ActorToken is not { Length: > 0 } actorToken)
            return ctx;

        var result = await ResolveTokenAsync(ctx.Request.ActorTokenType, actorToken, CancellationToken.None);
        return result.Match<Result<ValidationContext, OidcError>>(
            actor => ctx with { Actor = actor },
            failure => new OidcError(ErrorCodes.InvalidRequest, $"actor_token: {failure.ErrorDescription}"));
    }

    /// <summary>
    /// Applies the same origin + typ-header guards to the actor_token (when present) that
    /// <see cref="ValidateSubjectTokenOriginAndType"/> applies to the subject_token. No-op when
    /// the request had no actor.
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateActorTokenOriginAndType(ValidationContext ctx)
    {
        if (ctx.Actor is not { } actor)
            return ctx;

        return CheckTokenOriginAndType(actor, ctx.Request.ActorTokenType, ctx.ClientInfo) is { } error
            ? new OidcError(ErrorCodes.InvalidRequest, $"actor_token: {error.ErrorDescription}")
            : ctx;
    }

    /// <summary>
    /// Enforces the per-client <c>audience</c> allowlist (RFC 8693 §2.1). The requested audience is
    /// written into the issued token's <c>aud</c> claim, so it must be constrained — otherwise a
    /// client could mint a token for any target service it names. The allowlist is default-deny: an
    /// <c>audience</c> is accepted only when the client declares a non-empty
    /// <see cref="ClientInfo.TokenExchangeAllowedAudiences"/> that contains every requested value.
    /// A request without <c>audience</c> passes through. Rejections use <c>invalid_target</c>
    /// (RFC 8693 §2.2.1: the AS is unwilling to issue a token for the requested target service).
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateAudiences(ValidationContext ctx)
    {
        if (ctx.Request.Audiences is not { Length: > 0 } audiences)
            return ctx;

        if (ctx.ClientInfo.TokenExchangeAllowedAudiences is not { Length: > 0 } allowlist)
        {
            return new OidcError(
                ErrorCodes.InvalidTarget,
                "The client is not permitted to request an audience for token exchange.");
        }

        var allowed = new HashSet<string>(allowlist, StringComparer.Ordinal);
        var disallowed = audiences
            .Where(audience => !allowed.Contains(audience))
            .ToArray();

        if (disallowed.Length > 0)
        {
            // Report every disallowed audience, not just the first: a client fixing its request
            // should not have to re-submit and rediscover the rejected values one round-trip at a time.
            return new OidcError(
                ErrorCodes.InvalidTarget,
                $"The following audiences are not in the client's allow list: {string.Join(", ", disallowed)}.");
        }

        return ctx;
    }

    /// <summary>
    /// Shared origin + typ-header guards applied identically to subject and actor tokens.
    /// </summary>
    private static OidcError? CheckTokenOriginAndType(
        SubjectTokenContext token,
        string? requestedTypeUri,
        ClientInfo clientInfo)
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
        //   refresh_token -> rt+jwt
        //   jwt           -> any typ acceptable (generic JWT URI)
        // Resolvers for non-JWT formats leave JwtTokenType null; this check is a no-op for them.
        var expectedTyp = requestedTypeUri switch
        {
            TokenExchangeTokenTypes.AccessToken => JwtTypes.AccessToken,
            TokenExchangeTokenTypes.IdToken => JwtTypes.IdToken,
            TokenExchangeTokenTypes.RefreshToken => JwtTypes.RefreshToken,
            _ => null,
        };
        if (expectedTyp is not null &&
            token.JwtTokenType is { Length: > 0 } actualTyp &&
            !string.Equals(actualTyp, expectedTyp, StringComparison.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token has typ '{actualTyp}' but was presented under '{requestedTypeUri}' (expected typ '{expectedTyp}').");
        }

        return null;
    }

    private async Task<Result<SubjectTokenContext, OidcError>> ResolveTokenAsync(
        string? tokenType,
        string tokenValue,
        CancellationToken cancellationToken)
    {
        var resolver = serviceProvider.GetKeyedService<ISubjectTokenResolver>(tokenType);
        if (resolver is null)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"token_type '{tokenType}' is not supported.");
        }

        return await resolver.ResolveAsync(tokenValue, cancellationToken);
    }

    private AuthorizedGrant BuildAuthorizedGrant(ValidationContext ctx)
    {
        var subject = ctx.Subject.NotNull(nameof(ctx.Subject));
        var actor = ctx.Actor;
        var request = ctx.Request;
        var clientInfo = ctx.ClientInfo;

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

        // propagate the requested resource(s) (RFC 8707) through the ctor and audience(s)
        // (RFC 8693 §2.1) through the initializer into the issued token's claims rather than
        // silently dropping them
        var authContext = new AuthorizationContext(clientInfo.ClientId, scope, null, request.Resources)
        {
            AuthorizationDetails = subject.AuthorizationDetails,
            Actor = actorClaim,
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
