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
public sealed class JwtSubjectTokenResolver(IAuthServiceJwtValidator jwtValidator) : ISubjectTokenResolver
{
    /// <inheritdoc/>
    public string Type => TokenExchangeTokenTypes.Jwt;

    /// <inheritdoc/>
    public async Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        string subjectToken,
        CancellationToken cancellationToken)
    {
        var validation = await jwtValidator.ValidateAsync(subjectToken);
        if (!validation.TryGetSuccess(out var jwt))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The subject_token is invalid or has expired.");
        }

        var subject = jwt.Payload.Subject;
        if (string.IsNullOrWhiteSpace(subject))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "subject_token is missing the required 'sub' claim.");
        }

        // Direct raw access to authorization_details preserves byte-exact payload; DeepClone
        // detaches it from the subject_token's payload before it flows into a fresh
        // AuthorizationContext (and onward into a new JWT) -- without the clone System.Text.Json
        // rejects the second serialisation because the JsonNode is parented twice.
        var authorizationDetailsRaw =
            jwt.Payload.Json[IanaClaimTypes.AuthorizationDetails] is JsonArray ad
                ? (JsonArray?)ad.DeepClone()
                : null;

        return new SubjectTokenContext(
            Subject: subject,
            Issuer: jwt.Payload.Issuer,
            Scope: jwt.Payload.Scope?.ToArray(),
            AuthorizationDetailsRaw: authorizationDetailsRaw);
    }
}
