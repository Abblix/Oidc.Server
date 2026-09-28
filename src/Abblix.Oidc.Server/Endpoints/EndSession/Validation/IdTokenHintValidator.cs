// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Validates the <c>id_token_hint</c> parameter (OpenID Connect RP-Initiated Logout 1.0 section 2):
/// verifies signature/issuer/audience but deliberately accepts expired tokens (since the
/// hint's role is to identify a no-longer-active session), then either populates
/// <c>ClientId</c> from the token's audience when the request omitted it, or asserts that
/// an explicitly supplied <c>client_id</c> matches that audience.
/// </summary>
/// <remarks>
/// A client taken from the audience is not checked for registration here: <see cref="ClientValidator"/>
/// answers that for every request, and it reads the client this step sets, so it has to follow this one in
/// the family. A host that removes it or moves it ahead of this step passes an unregistered audience through
/// validation, and a step it inserts right after this one reads a client nobody has checked yet.
/// </remarks>
public class IdTokenHintValidator(IIdTokenHintParser hintParser) : IEndSessionContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
    {
        var request = context.Request;

        if (request.IdTokenHint.HasValue())
        {
            // The audience is checked below rather than by the parser, which leaves it to its callers
            // because they disagree about it. An ID token is the one type that names a client there:
            // OpenID Connect Core 1.0 Section 2 says the aud claim "MUST contain the OAuth 2.0 client_id
            // of the Relying Party".
            var result = await hintParser.ParseAsync(request.IdTokenHint);
            if (result.TryGetFailure(out var reason))
                return new OidcError(ErrorCodes.InvalidRequest, reason);

            var idToken = result.GetSuccess();

            var audiences = idToken.Payload.Audiences;
            if (!request.ClientId.HasValue())
            {
                try
                {
                    context.ClientId = audiences.Single();
                }
                catch (Exception)
                {
                    return new OidcError(
                        ErrorCodes.InvalidRequest,
                        "The audience in the id token hint is missing or have multiple values.");
                }
            }
            else if (!audiences.Contains(request.ClientId, StringComparer.Ordinal))
            {
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "The id token hint contains token issued for the client other than specified");
            }

            context.IdToken = idToken;
        }

        return null;
    }
}
