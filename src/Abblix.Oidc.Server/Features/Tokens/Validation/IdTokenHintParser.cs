// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Decides whether an <c>id_token_hint</c> is an ID token this server issued.
/// </summary>
/// <remarks>
/// Three questions, in the order that makes each one cheap. Is it ours - signature and issuer. Is it an ID
/// token rather than another kind of JWT we sign with the same key. And does it carry the claim an ID token
/// is required to carry, which is what parts it from the one other kind that has no type either.
/// <para>
/// Who the audience must name is left to the caller, because the two callers disagree. The authorization
/// endpoint requires the requesting client; the end-session endpoint reads the client out of the audience
/// when the request omitted it. What both agree on is that this server need not be in it - OpenID Connect
/// Core 1.0 Section 3.1.2.1: "The Authorization Server need not be listed as an audience of the ID Token
/// when it is used as an <c>id_token_hint</c> value."
/// </para>
/// </remarks>
/// <param name="jwtValidator">Validates the hint's signature and issuer.</param>
public class IdTokenHintParser(IAuthServiceJwtValidator jwtValidator) : IIdTokenHintParser
{
    /// <summary>
    /// What a hint has to satisfy beyond an ordinary own-issued token.
    /// </summary>
    /// <remarks>
    /// The lifetime is not validated, because a hint names an end user rather than a live credential: an ID
    /// token from a session that ended hours ago identifies them exactly as well as a fresh one, and holding
    /// on to it is the whole reason a client has one to send.
    /// <para>
    /// The audience is not validated here either - see the class remarks - but an expiration time is
    /// required to be present. OpenID Connect Core 1.0 Section 2 makes <c>exp</c> REQUIRED in an ID Token,
    /// and requiring it while ignoring its value is what parts an ID token from a signed UserInfo response,
    /// which Section 5.3.2 requires to carry <c>iss</c> and <c>aud</c> and nothing more. RFC 8725
    /// Section 3.12 names a claim as an equal way to keep the validation rules of two kinds of JWT mutually
    /// exclusive.
    /// </para>
    /// </remarks>
    private const ValidationOptions HintOptions =
        (ValidationOptions.Default & ~ValidationOptions.ValidateLifetime & ~ValidationOptions.ValidateAudience)
        | ValidationOptions.RequireExpirationTime;

    /// <inheritdoc />
    public async Task<Result<JsonWebToken, string>> ParseAsync(string idTokenHint)
    {
        var result = await jwtValidator.ValidateAsync(idTokenHint, HintOptions);
        if (result.TryGetFailure(out var validationError))
            return $"The id token hint contains an invalid token: {validationError}";

        var idToken = result.GetSuccess();

        // RFC 8725 Section 3.12 on the header this time: another own-issued token whose audience happens to
        // match - an access or refresh token - must not be replayable here, which signature alone would not
        // catch.
        if (!JwtTypes.IsPermitted(idToken.Header.Type))
            return "The id token hint is not an ID Token";

        return idToken;
    }
}
