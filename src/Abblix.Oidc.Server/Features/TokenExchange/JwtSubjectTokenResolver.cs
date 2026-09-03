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
using Abblix.Oidc.Server.Features.Licensing;
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
    /// An RFC 8693 subject_token was minted for a client or, under RFC 8707, for a resource server
    /// -- never for this AS as its audience. Enforcing the default "aud must be a registered client"
    /// rule would wrongly reject a resource-scoped access token presented for exchange. The token's
    /// binding to the requesting client is enforced separately by the confused-deputy guard in
    /// <see cref="Endpoints.Token.Grants.TokenExchangeGrantHandler"/>, so here we validate signature,
    /// issuer and lifetime but deliberately drop the audience constraint.
    /// </summary>
    private const ValidationOptions SubjectTokenValidation =
        ValidationOptions.Default & ~ValidationOptions.RequireValidAudience;

    /// <inheritdoc/>
    public async Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        string subjectToken,
        CancellationToken cancellationToken)
    {
        var validation = await jwtValidator.ValidateAsync(subjectToken, SubjectTokenValidation);
        if (!validation.TryGetSuccess(out var jwt))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The subject_token is invalid or has expired.");
        }

        var subject = jwt.Payload.Subject;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "subject_token is missing the required 'sub' claim.");
        }

        // The client the subject_token names (client_id, else azp, else the sole audience): used both to open a
        // pairwise 'sub' back to the real subject and as the confused-deputy origin below.
        var originalClientId = jwt.Payload.ClientId ?? jwt.Payload.AuthorizedParty ?? SingleAudience(jwt);

        // When the subject_token was issued to a pairwise client, 'sub' is that client's per-sector pseudonym; open
        // it against that client's sector. id_tokens, plain JWTs and public-client tokens carry the real subject
        // and pass through unchanged.
        var originalClient = originalClientId is not null
            ? await clientInfoProvider.TryFindClientAsync(originalClientId).WithLicenseCheck()
            : null;

        if (originalClient is not null)
        {
            // A pairwise 'sub' that does not open for its client (a foreign-sector or pre-change token) is rejected
            // rather than faulting the exchange.
            var recovered = subjectTypeConverter.ConvertBack(subject, originalClient);
            if (recovered is null)
                return new OidcError(
                    ErrorCodes.InvalidRequest, "The subject_token's subject could not be resolved.");

            subject = recovered;
        }

        // Direct raw access to authorization_details preserves byte-exact payload; DeepClone
        // detaches it from the subject_token's payload before it flows into a fresh
        // AuthorizationContext (and onward into a new JWT) -- without the clone System.Text.Json
        // rejects the second serialisation because the JsonNode is parented twice.
        var authorizationDetails = Extract<JsonArray>(jwt, IanaClaimTypes.AuthorizationDetails);

        // RFC 8693 section 4.1 act chain: preserve the subject_token's act so a delegation chain can
        // be extended when this resolver feeds a Token Exchange request that also supplies an
        // actor_token. DeepClone for the same parenting reason as AD.
        var act = Extract<JsonObject>(jwt, IanaClaimTypes.Act);

        return new SubjectTokenContext(
            Subject: subject,
            Issuer: jwt.Payload.Issuer,
            Scope: jwt.Payload.Scope?.ToArray(),
            AuthorizationDetails: authorizationDetails)
        {
            Act = act,

            // Origin tracking for the confused-deputy guard. Access and refresh tokens name their
            // client in the client_id claim, but an id_token carries no such claim -- it identifies
            // its client through a sole audience, or through azp when several audiences are present.
            // Without this fallback the guard would silently skip every id_token exchange, letting
            // any client exchange any user's id_token. The preference order matches how each token
            // shape encodes its client; a token with several audiences and neither client_id nor azp
            // stays null, i.e. its origin is genuinely undeterminable.
            OriginalClientId = originalClientId,

            // typ header for cross-type confusion check (e.g. id+jwt presented as access_token).
            JwtTokenType = jwt.Header.Type,
        };
    }

    private static T? Extract<T>(JsonWebToken jwt, string name) where T: JsonNode
        => jwt.Payload.Json[name] is T node ? (T?)node.DeepClone() : null;

    /// <summary>
    /// Returns the sole audience of the token, or null when there is none or more than one. A
    /// single-audience own-issued token (id_token, logout_token) puts the client there; multiple
    /// audiences are ambiguous, so origin is determined from azp instead (handled by the caller).
    /// </summary>
    private static string? SingleAudience(JsonWebToken jwt)
    {
        string? single = null;
        foreach (var audience in jwt.Payload.Audiences)
        {
            if (single is not null)
                return null;

            single = audience;
        }

        return single;
    }
}
