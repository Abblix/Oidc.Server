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
/// <param name="hintParser">Decides whether the hint is an ID token this server issued.</param>
public class IdTokenHintValidator(IIdTokenHintParser hintParser) : IAuthorizationContextValidator
{
    /// <inheritdoc />
    public async Task<AuthorizationRequestValidationError?> ValidateAsync(AuthorizationValidationContext context)
    {
        if (!context.Request.IdTokenHint.HasValue())
            return null;

        var result = await hintParser.ParseAsync(context.Request.IdTokenHint);
        if (result.TryGetFailure(out var reason))
            return context.InvalidRequest(reason);

        var idToken = result.GetSuccess();

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
