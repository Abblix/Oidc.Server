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
    /// The audience is not validated here either - see the class remarks. The expiration time is required
    /// too, but by <see cref="ParseAsync"/> rather than by <see cref="ValidationOptions.RequireExpirationTime"/>
    /// here, so that it is asked AFTER the type. The library would refuse a token missing <c>exp</c> before
    /// anything looked at what kind of token it is, and this server mints one own-issued kind that carries no
    /// <c>exp</c> by default - a registration access token, which RFC 7592 Section 5 says SHOULD NOT expire.
    /// Presented as a hint, that token would be refused for a missing expiry, telling its sender to add a
    /// claim the specification tells this server to leave out, when the real answer is that it is the wrong
    /// kind of token entirely.
    /// </para>
    /// </remarks>
    private const ValidationOptions HintOptions =
        ValidationOptions.Default & ~ValidationOptions.ValidateLifetime & ~ValidationOptions.ValidateAudience;

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

        // The one own-issued kind a type check cannot reach is a signed UserInfo response, which carries no
        // type either and is signed with the same key for the same client. What parts the two is a claim
        // rather than a header, which RFC 8725 Section 3.12 lists as an equal way to keep the validation
        // rules of two kinds of JWT mutually exclusive: OpenID Connect Core 1.0 Section 2 makes exp REQUIRED
        // in an ID Token, while Section 5.3.2 requires a signed UserInfo response to carry iss and aud and
        // nothing more.
        //
        // Presence alone is the test - a hint is accepted after expiry on purpose, since it names a session
        // that has ended - so the lifetime check stays switched off above.
        if (idToken.Payload.ExpiresAt is null)
            return "The id token hint is not an ID Token: it has no expiration time";

        return idToken;
    }
}
