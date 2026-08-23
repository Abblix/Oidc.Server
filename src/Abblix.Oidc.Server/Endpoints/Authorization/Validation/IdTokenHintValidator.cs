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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the <c>id_token_hint</c> parameter of an authorization request and records the end user it
/// names, so the endpoint can honour it when it chooses a session.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 Section 3.1.2.1 on <c>id_token_hint</c>: "If the End-User identified by the ID
/// Token is logged in or is logged in by the request, then the Authorization Server returns a positive
/// response; otherwise, it SHOULD return an error, such as <c>login_required</c>." Without this the
/// parameter was parsed and consumed nowhere, so a request naming one end user could be answered for
/// another - which stays invisible while a browser holds a single session and stops being invisible as soon
/// as it holds two.
/// <para>
/// The subject is recorded as the ID token spells it, which for a pairwise client is the pseudonym sealed to
/// that client's sector rather than the subject a session carries. Converting the session forward when they
/// are compared is what keeps the two comparable; opening the pseudonym instead would fail whenever it could
/// not be opened, and failing to compare must not read as a match.
/// </para>
/// <para>
/// After <see cref="ClientValidator"/>, which resolves the <see cref="AuthorizationValidationContext.ClientInfo"/>
/// this needs to check the audience against.
/// </para>
/// </remarks>
/// <param name="jwtValidator">Validates the hint's signature and issuer.</param>
public class IdTokenHintValidator(IAuthServiceJwtValidator jwtValidator) : IAuthorizationContextValidator
{
    /// <inheritdoc />
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        if (!context.Request.IdTokenHint.HasValue())
            return null;

        // The lifetime is deliberately not validated. A hint names an end user, not a live credential, and
        // an ID token from a session that ended hours ago identifies them exactly as well as a fresh one -
        // which is the whole reason a client holds on to it. The audience is checked below rather than by
        // the shared validator, which accepts only the issuer.
        var result = await jwtValidator.ValidateAsync(
            context.Request.IdTokenHint,
            ValidationOptions.Default & ~ValidationOptions.ValidateLifetime & ~ValidationOptions.ValidateAudience);

        if (result.TryGetFailure(out var validationError))
            return context.InvalidRequest($"The id token hint contains an invalid token: {validationError}");

        var idToken = result.GetSuccess();

        // RFC 8725 Section 3.12: keep the validation rules for different kinds of JWT mutually exclusive, so
        // another own-issued token whose audience happens to match - an access or refresh token - cannot be
        // replayed here, which signature and audience alone would not catch.
        if (!JwtTypes.IsPermitted(idToken.Header.Type))
            return context.InvalidRequest("The id token hint is not an ID Token");

        // The one other own-issued JWT carrying no type is a signed UserInfo response, signed with the same
        // key and addressed to the same client. What parts the two is a claim rather than a header, which
        // RFC 8725 Section 3.12 lists as an equal way to keep the rules exclusive: OpenID Connect Core 1.0
        // Section 2 makes exp REQUIRED in an ID Token, while Section 5.3.2 requires a signed UserInfo
        // response to carry iss and aud and nothing more.
        if (idToken.Payload.ExpiresAt is null)
            return context.InvalidRequest("The id token hint is not an ID Token: it has no expiration time");

        // OpenID Connect Core 1.0 Section 2: an ID Token's aud "MUST contain the OAuth 2.0 client_id of the
        // Relying Party". A hint addressed to somebody else names a session this client has no business
        // naming, whether or not it identifies a real end user.
        if (!idToken.Payload.Audiences.Contains(context.ClientInfo.ClientId, StringComparer.Ordinal))
            return context.InvalidRequest("The id token hint was issued for another client");

        if (idToken.Payload.Subject is not { Length: > 0 } subject)
            return context.InvalidRequest("The id token hint names no subject");

        context.IdTokenHintSubject = subject;
        return null;
    }
}
