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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// <see cref="ISubjectTokenResolver"/> for JWT-formatted subject tokens. Validates the JWT via
/// <see cref="IAuthServiceJwtValidator"/> (signature, lifetime, registered claims) and projects
/// the payload's <c>sub</c>, <c>scope</c>, and <c>authorization_details</c> claims into a
/// <see cref="SubjectTokenContext"/>.
/// </summary>
/// <remarks>
/// Used for three RFC 8693 token-type URIs that share the JWT validation path:
/// <see cref="TokenExchangeTokenTypes.AccessToken"/>, <see cref="TokenExchangeTokenTypes.IdToken"/>,
/// and <see cref="TokenExchangeTokenTypes.Jwt"/>. The same instance is registered under all three
/// keyed-DI keys (see <c>AddTokenExchangeGrant</c>); the <see cref="Type"/> property reports the
/// instance's primary key so dispatch logging stays readable.
/// </remarks>
/// <param name="jwtValidator">Validates own-issued JWTs (signature against AS keys, claims).</param>
/// <param name="subjectTypeConverter">Opens a pairwise subject_token's <c>sub</c> back to the real subject.</param>
/// <param name="clientInfoProvider">Resolves the client the subject_token was issued to, whose sector opens its
/// pairwise subject.</param>
public sealed class JwtSubjectTokenResolver(
    IAuthServiceJwtValidator jwtValidator,
    ISubjectTypeConverter subjectTypeConverter,
    IClientInfoProvider clientInfoProvider) : ISubjectTokenResolver
{
    /// <summary>
    /// The token types a subject token presented under <paramref name="tokenType"/> may carry, so a token issued
    /// for one purpose is not exchanged as another.
    /// </summary>
    /// <remarks>
    /// An access token is typed <c>at+jwt</c> (RFC 9068 section 2.1); an ID token carries what
    /// <see cref="JwtTypes.IdTokens"/> allows. The generic JWT type accepts either of those.
    /// </remarks>
    private static TokenTypePolicy? TokenTypesOf(string tokenType) => tokenType switch
    {
        TokenExchangeTokenTypes.AccessToken => TokenTypePolicy.Exactly(JsonWebTokenTypes.AccessToken),
        TokenExchangeTokenTypes.IdToken => JwtTypes.IdTokens,
        TokenExchangeTokenTypes.Jwt => TokenTypePolicy.OrUntyped(JsonWebTokenTypes.AccessToken, JsonWebTokenTypes.Jwt),
        _ => null,
    };

    /// <inheritdoc/>
    public async Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        TenantDefinition tenant,
        ClientInfo client,
        [Credential] string subjectToken,
        Uri tokenType,
        CancellationToken cancellationToken)
    {
        if (TokenTypesOf(tokenType.OriginalString) is not { } accepted)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest, $"The token type '{tokenType}' is not a JWT this server reads.");
        }

        // An RFC 8693 subject_token may name a client (an ID token) or, under RFC 8707, a resource server in its
        // audience rather than this server, so a resource-scoped access token presented for exchange is not refused
        // for it. Its binding to the requesting client is enforced by the confused-deputy guard in
        // TokenExchangeGrantHandler.
        var validation = await jwtValidator.ValidateAsync(
            tenant,
            client,
            subjectToken,
            accepted,
            ServiceTokenValidation.AnyAudience);
        if (!validation.TryGetSuccess(out var jwt))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The token is invalid or has expired.");
        }

        // A revocation of a session reaches a token through the session it names. Every token this server issues
        // for a session names it, the ID token of a client that does not use the session at logout excepted, so a
        // token naming none cannot be checked against a session revocation and would keep working after one. It is
        // refused whichever role it plays in the exchange, subject or actor.
        if (jwt.Payload.SessionId is not { Length: > 0 } sessionId)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The token names no session, so a revocation of its session could not be checked.");
        }

        // The exchanged token tells when the end user signed in, and a token that does not say could only be answered
        // with the moment of the exchange, which would present an old sign-in as a fresh one.
        if (jwt.Payload.AuthenticationTime is not { } authenticationTime)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The token states no authentication time, so the token exchanged from it could not state one.");
        }

        if (string.IsNullOrWhiteSpace(jwt.Payload.Subject))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The token is missing the required 'sub' claim.");
        }

        // The client the subject_token belongs to: used both to open pairwise identifiers back to the real parties and
        // as the confused-deputy origin below.
        var originalClientId = jwt.OwnerOf();

        var opened = await OpenSubjectsAsync(tenant, jwt.Payload, originalClientId);
        if (opened.TryGetFailure(out var openError))
        {
            return openError;
        }

        var real = opened.GetSuccess();

        // Direct raw access to authorization_details preserves byte-exact payload; DeepClone
        // detaches it from the subject_token's payload before it flows into a fresh
        // AuthorizationContext (and onward into a new JWT) -- without the clone System.Text.Json
        // rejects the second serialisation because the JsonNode is parented twice.
        var authorizationDetails = Extract<JsonArray>(jwt, IanaClaimTypes.AuthorizationDetails);

        return new SubjectTokenContext(
            Subject: real.Subject,
            Issuer: jwt.Payload.Issuer,
            // A scope claim holding no scope is still the token's scope, unlike a token carrying no scope claim
            Scope: jwt.Payload.Json.ContainsKey(IanaClaimTypes.Scope) ? [.. jwt.Payload.Scope] : null,
            AuthorizationDetails: authorizationDetails)
        {
            // RFC 8693 section 4.1 act chain, opened to the real actors: the exchanged token keeps it, and extends it
            // when the request also supplies an actor_token.
            Act = real.Actor,

            // Origin tracking for the confused-deputy guard. Access and refresh tokens name their
            // client in the client_id claim, but an id_token carries no such claim -- it identifies
            // its client through a sole audience, or through azp when several audiences are present.
            // Without this fallback the guard would silently skip every id_token exchange, letting
            // any client exchange any user's id_token. The preference order matches how each token
            // shape encodes its client; a token with several audiences and neither client_id nor azp
            // stays null, i.e. its origin is genuinely undeterminable.
            OriginalClientId = originalClientId,

            // Whom the token is addressed to, which a client exchanging tokens issued for it as a resource server is
            // matched by
            Audiences = [.. jwt.Payload.Audiences],

            // The family this token carries, taken into the exchanged token so a revoked family refuses it too.
            GrantId = jwt.Payload.GrantId,
            ExpiresAt = jwt.Payload.ExpiresAt,
            SessionId = sessionId,
            AuthenticationTime = authenticationTime,
            IdentityProvider = jwt.Payload.IdentityProvider,
            AuthContextClassRef = jwt.Payload.AuthContextClassRef,
            AuthenticationMethodReferences = jwt.Payload.AuthenticationMethodReferences?.ToList(),
        }.BoundAs(jwt.Payload);
    }

    /// <summary>
    /// The real parties behind the token's <c>sub</c> and <c>act</c>, or the reason they cannot be told.
    /// </summary>
    /// <remarks>
    /// When the token was issued to a pairwise client, 'sub' and every actor are that client's per-sector
    /// pseudonyms, opened against that client's sector - not the requesting client's, which differs in a cross-client
    /// exchange. A public client's token carries the real parties, which opening leaves as they are, and so does a
    /// token naming no client at all, which no pairwise client was issued.
    /// <para>
    /// Only the sector of the client the token names opens its pairwise identifiers, so a token naming a client this
    /// server no longer knows is refused rather than exchanged with its pseudonyms taken for the real parties and
    /// sealed a second time. So is a pairwise 'sub' or actor that does not open for its client (a foreign-sector or
    /// pre-change token).
    /// </para>
    /// </remarks>
    private async Task<Result<TokenSubjects, OidcError>> OpenSubjectsAsync(
        TenantDefinition tenant,
        JsonWebTokenPayload payload,
        string? originalClientId)
    {
        var seen = TokenSubjects.Of(payload);
        if (originalClientId is null)
            return seen;

        if (!(await clientInfoProvider.FindClientAsync(tenant, originalClientId)).TryGetSuccess(out var originalClient))
            return new OidcError(ErrorCodes.InvalidRequest, "The token's client is not known.");

        if (subjectTypeConverter.Open(tenant, seen, originalClient) is not { } real)
            return new OidcError(ErrorCodes.InvalidRequest, "The token's subject could not be resolved.");

        return real;
    }

    private static T? Extract<T>(JsonWebToken jwt, string name) where T: JsonNode
        => jwt.Payload.Json[name] is T node ? (T?)node.DeepClone() : null;

}
