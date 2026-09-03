// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
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
/// Supports both RFC 8693 section 4.1 modes: impersonation (no <c>actor_token</c>; the issued token's
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
        ClientInfo clientInfo,
        CancellationToken cancellationToken)
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
    /// RFC 8693 section 2.1: <c>subject_token</c> and <c>subject_token_type</c> are REQUIRED. A missing one
    /// is the caller's protocol error (<c>invalid_request</c> per RFC 6749 section 5.2), not a server
    /// fault - the previous throw-on-access surfaced it as HTTP 500.
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
    /// RFC 8693 section 2.1: <c>actor_token</c> and <c>actor_token_type</c> are mutually required when
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
    /// Enforces the per-client <c>audience</c> allowlist (RFC 8693 section 2.1). The requested audience is
    /// written into the issued token's <c>aud</c> claim, so it must be constrained - otherwise a
    /// client could mint a token for any target service it names. The allowlist is default-deny: an
    /// <c>audience</c> is accepted only when the client declares a non-empty
    /// <see cref="ClientInfo.TokenExchangeAllowedAudiences"/> that contains every requested value.
    /// RFC 8707 <c>resource</c> values reach the <c>aud</c> claim through the exact same path
    /// (see <c>AuthorizationContextExtensions.ApplyTo</c>), so a declared allowlist gates them too -
    /// otherwise renaming <c>audience</c> to <c>resource</c> would bypass the constraint entirely.
    /// A client without a declared allowlist keeps the asymmetric defaults: <c>audience</c> is
    /// default-deny because no other gate exists for logical service names, while <c>resource</c>
    /// stays subject to the global resource registry (<c>ResourceValidator</c> has already checked
    /// it earlier in the token pipeline). A request without either parameter passes through.
    /// Rejections use <c>invalid_target</c> (RFC 8693 section 2.2.1: the AS is unwilling to issue a token
    /// for the requested target service).
    /// </summary>
    private static Result<ValidationContext, OidcError> ValidateAudiences(ValidationContext ctx)
    {
        var audiences = ctx.Request.Audiences ?? [];
        var resources = ctx.Request.Resources ?? [];

        if (audiences.Length == 0 && resources.Length == 0)
            return ctx;

        if (ctx.ClientInfo.TokenExchangeAllowedAudiences is not { Length: > 0 } allowlist)
        {
            if (audiences.Length == 0)
                return ctx;

            return new OidcError(
                ErrorCodes.InvalidTarget,
                "The client is not permitted to request an audience for token exchange.");
        }

        var allowed = new HashSet<string>(allowlist, StringComparer.Ordinal);
        var disallowed = audiences
            .Concat(Array.ConvertAll(resources, resource => resource.OriginalString))
            .Where(target => !allowed.Contains(target))
            .ToArray();

        if (disallowed.Length > 0)
        {
            // Report every disallowed target, not just the first: a client fixing its request
            // should not have to re-submit and rediscover the rejected values one round-trip at a time.
            return new OidcError(
                ErrorCodes.InvalidTarget,
                $"The following target services are not in the client's allow list: {string.Join(", ", disallowed)}.");
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
        // The confused-deputy check needs an origin to compare against, and an absent one is the case
        // it cannot decide: a token whose issuing client is undeterminable may or may not belong to the
        // presenting client, and the guard exists precisely because the difference matters. Refusing is
        // the only reading that keeps the check meaningful - skipping on absence would let a subject_token
        // shaped to hide its origin pass the guard that a token naming another client fails.
        // AllowCrossClientSubjectTokenExchange remains the single opt-out: a client trusted to present
        // tokens it was not issued is equally trusted to present one whose issuer cannot be read.
        if (!clientInfo.AllowCrossClientSubjectTokenExchange)
        {
            if (token.OriginalClientId is not { Length: > 0 } originalClient)
            {
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The client the subject_token was issued to could not be determined.");
            }

            if (!string.Equals(originalClient, clientInfo.ClientId, StringComparison.Ordinal))
            {
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "subject_token was issued to a different client than the one presenting it.");
            }
        }

        // typ header expected per URI (JWT-based subject types only):
        //   access_token  -> at+jwt
        //   refresh_token -> the refresh class this server issues
        //   id_token      -> nothing to expect: an ID token carries no type of its own
        //   jwt           -> any typ acceptable (generic JWT URI)
        // Resolvers for non-JWT formats leave JwtTokenType null; this check is a no-op for them.
        var expectedTyp = requestedTypeUri switch
        {
            TokenExchangeTokenTypes.AccessToken => JsonWebTokenTypes.AccessToken,
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

        // RFC 8693 section 4.1: issued token's subject is always the subject_token's subject (impersonation
        // and delegation alike). Scope handling keeps the exchange least-privilege - the issued token
        // never carries more authority than either the presented subject_token or the client's own
        // registration:
        //
        // - Explicit request.Scope (2a): already gated against the client's AllowedScopes by
        //   ScopeValidator in the token pipeline. Additionally bound it to the subject_token's own
        //   scope WHEN the subject token carries one, so an exchange cannot amplify authority beyond
        //   the presented token. A subject token without a scope claim (e.g. an id_token) imposes no
        //   scope upper bound, so the RFC 8693 id_token -> access_token scenario keeps working.
        // - Fallback to the subject_token's scope (2b): the fallback path does not pass through
        //   ScopeValidator, so it is filtered to the client's AllowedScopes here - otherwise a broker
        //   client would obtain scopes it was never registered for (RFC 6749 section 3.3).
        string[] scope;
        if (request.Scope is { Length: > 0 } requestedScope)
        {
            scope = subject.Scope is { Length: > 0 } subjectScope
                ? IntersectScopes(requestedScope, subjectScope)
                : requestedScope;
        }
        else
        {
            scope = FilterToAllowedScopes(subject.Scope, clientInfo.AllowedScopes);
        }

        // Delegation act chain (RFC 8693 section 4.1): when an actor_token was supplied, the new actor's
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
        // (RFC 8693 section 2.1) through the initializer into the issued token's claims rather than
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

    /// <summary>
    /// Restricts a scope set inherited from the subject_token to the requesting client's registered
    /// <see cref="ClientInfo.AllowedScopes"/>. A null or empty allow-list means "no per-client
    /// restriction" (matching <c>ScopeManager.Validate</c> and the JWT bearer grant), so the inherited
    /// scope passes through unchanged. Comparison is ordinal per RFC 6749 section 3.3 scope-token semantics.
    /// </summary>
    private static string[] FilterToAllowedScopes(string[]? inheritedScope, string[]? allowedScopes)
    {
        if (inheritedScope is not { Length: > 0 })
            return [];

        if (allowedScopes is not { Length: > 0 })
            return inheritedScope;

        return Array.FindAll(inheritedScope, scope => Array.IndexOf(allowedScopes, scope) >= 0);
    }

    /// <summary>
    /// Intersects the explicitly requested scope with the subject_token's own scope, keeping only the
    /// requested values the subject token also holds. Caller applies this only when the subject token
    /// carries a scope; a scopeless subject token (e.g. an id_token) imposes no upper bound. Comparison
    /// is ordinal per RFC 6749 section 3.3 scope-token semantics.
    /// </summary>
    private static string[] IntersectScopes(string[] requestedScope, string[] subjectScope)
        => Array.FindAll(requestedScope, scope => Array.IndexOf(subjectScope, scope) >= 0);
}
