// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
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
/// OpenID Connect Core 1.0 Section 3.1.2.1: "If the End-User identified by the ID Token is already logged in
/// or is logged in as a result of the request (with the OP possibly evaluating other information beyond the
/// ID Token in this decision), then the Authorization Server returns a positive response; otherwise, it MUST
/// return an error, such as <c>login_required</c>." A parameter parsed and read by nobody leaves a request
/// naming one end user answerable for another, which costs nothing while a browser holds one session and
/// stops costing nothing as soon as it holds two.
/// <para>
/// The subject is recorded as the ID token spells it, which for a pairwise client is the pseudonym sealed to
/// that client's sector rather than the subject a session carries. Whoever compares the two converts the
/// session forward.
/// </para>
/// <para>
/// Runs after the validators that resolve the redirect URI and the response mode, because its refusals are
/// the kind RFC 6749 Section 4.1.2.1 says the client must be told about, and before them there is nowhere to
/// tell it. The <see cref="AuthorizationValidationContext.ClientInfo"/> it reads is resolved earlier still.
/// </para>
/// </remarks>
/// <param name="jwtValidator">Validates the hint's signature and issuer.</param>
public class IdTokenHintValidator(IAuthServiceJwtValidator jwtValidator) : IAuthorizationContextValidator
{
    /// <summary>
    /// What a hint has to satisfy beyond an ordinary own-issued token.
    /// </summary>
    /// <remarks>
    /// The lifetime is not validated, because a hint names an end user rather than a live credential: an ID
    /// token from a session that ended hours ago identifies them exactly as well as a fresh one, and holding
    /// on to it is the whole reason a client has one to send.
    /// <para>
    /// The audience is not validated either, because this server is not in it. OpenID Connect Core 1.0
    /// Section 3.1.2.1: "The Authorization Server need not be listed as an audience of the ID Token when it
    /// is used as an <c>id_token_hint</c> value." Who the audience must contain is checked below, against
    /// the requesting client rather than against this server.
    /// </para>
    /// <para>
    /// An expiration time is required instead. Section 2 makes <c>exp</c> REQUIRED in an ID Token, and
    /// requiring its presence while ignoring its value is what parts an ID token from the one other
    /// own-issued JWT that carries no type either - a signed UserInfo response, which Section 5.3.2 requires
    /// to carry <c>iss</c> and <c>aud</c> and nothing more. RFC 8725 Section 3.12 names a claim as an equal
    /// way to keep the validation rules of two kinds of JWT mutually exclusive.
    /// </para>
    /// </remarks>
    private const ValidationOptions HintOptions =
        (ValidationOptions.Default & ~ValidationOptions.ValidateLifetime & ~ValidationOptions.ValidateAudience)
        | ValidationOptions.RequireExpirationTime;

    /// <inheritdoc />
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        if (!context.Request.IdTokenHint.HasValue())
            return null;

        var result = await jwtValidator.ValidateAsync(context.Request.IdTokenHint, HintOptions);
        if (result.TryGetFailure(out var validationError))
            return context.InvalidRequest($"The id token hint contains an invalid token: {validationError}");

        var idToken = result.GetSuccess();

        // RFC 8725 Section 3.12 again, on the header this time: another own-issued token whose audience
        // happens to match - an access or refresh token - must not be replayable here, which signature and
        // audience alone would not catch.
        if (!JwtTypes.IsPermitted(idToken.Header.Type))
            return context.InvalidRequest("The id token hint is not an ID Token");

        // OpenID Connect Core 1.0 Section 2: an ID Token's aud "MUST contain the OAuth 2.0 client_id of the
        // Relying Party". A hint addressed to somebody else names a session this client has no business
        // naming, whether or not it identifies a real end user.
        if (!idToken.Payload.Audiences.Contains(context.ClientInfo.ClientId, StringComparer.Ordinal))
            return context.InvalidRequest("The id token hint was issued for another client");

        // The last untyped own-issued shape that clears everything above is a JARM response JWT, which
        // carries exp and this client's audience and no type. It has no sub, so this is what stops it - the
        // header gate is not.
        if (idToken.Payload.Subject is not { Length: > 0 } subject)
            return context.InvalidRequest("The id token hint names no subject");

        context.IdTokenHintSubject = subject;
        return null;
    }
}
