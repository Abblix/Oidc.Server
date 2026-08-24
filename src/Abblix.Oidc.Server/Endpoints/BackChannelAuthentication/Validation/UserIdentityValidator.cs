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
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the user's identity in a backchannel authentication request, ensuring that valid identity hints
/// (e.g., login hints, tokens) are provided and correctly processed.
/// </summary>
/// <param name="hintParser">Decides whether an <c>id_token_hint</c> is an ID token this server issued.</param>
/// <param name="clientJwtValidator">Validator for JWTs issued by clients.</param>
public class UserIdentityValidator(
    IIdTokenHintParser hintParser,
    IClientJwtValidator clientJwtValidator): IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Validates the user's identity based on the provided identity hints, such as login hint, login hint token,
    /// or ID token hint. It ensures that only one identity hint is present and attempts to process the hint
    /// to confirm the user's identity.
    /// </summary>
    /// <param name="context">Contains the backchannel authentication request and client information.</param>
    /// <returns>
    /// Returns a <see cref="OidcError"/> if the identity validation fails,
    /// or null if the identity is successfully validated.
    /// </returns>
    public async Task<OidcError?> ValidateAsync(
        BackChannelAuthenticationValidationContext context)
    {
        var request = context.Request;

        // Count the number of identity hints (LoginHint, LoginHintToken, IdTokenHint) provided in the request
        var userIdentityCount = new[]
            {
                request.LoginHint,        // Regular login hint
                request.LoginHintToken,   // JWT-based login hint token
                request.IdTokenHint       // ID token hint provided by the client
            }
            .Count(id => id.HasValue());

        switch (userIdentityCount)
        {
            case 1:
                break; // Valid scenario: exactly one hint is provided

            case 0:
                // No identity hint is present; return an error indicating the user's identity is unknown
                return new OidcError(
                    ErrorCodes.InvalidRequest, "The user's identity is unknown.");

            default:
                // Multiple identity hints provided; return an error indicating ambiguity
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "User identity is not determined due to conflicting hints.");
        }

        // Validate the LoginHintToken if it is provided and the client is configured to parse it as a JWT
        if (request.LoginHintToken.HasValue() && context.ClientInfo.ParseLoginHintTokenAsJwt)
        {
            var loginHintTokenResult = await clientJwtValidator.ValidateAsync(request.LoginHintToken);

            if (loginHintTokenResult.TryGetSuccess(out var validJwt))
            {
                // The token was issued for another client
                if (validJwt.Client.ClientId != context.ClientInfo.ClientId)
                {
                    return new OidcError(
                        ErrorCodes.InvalidRequest,
                        "LoginHintToken issued by another client.");
                }

                // If the token is valid and issued for the correct client, store it in the validation context
                context.LoginHintToken = validJwt.Token;
            }
            else
            {
                // The client opted into JWT parsing (ParseLoginHintTokenAsJwt), so any
                // validation failure - including a malformed / forged token surfacing as
                // InvalidToken - is rejected rather than silently treated as "no usable hint".
                return new OidcError(
                    ErrorCodes.InvalidRequest,
                    "LoginHintToken validation failed.");
            }
        }

        // Validate the IdTokenHint if present
        if (request.IdTokenHint.HasValue())
        {
            var idTokenResult = await ValidateIdTokenHint(context, request.IdTokenHint);
            if (idTokenResult.TryGetFailure(out var error))
            {
                return new OidcError(error.Error, error.ErrorDescription);
            }

            context.IdToken = idTokenResult.GetSuccess();
        }

        return null; // Identity validation successful
    }

    /// <summary>
    /// Validates the ID token hint to ensure it is properly issued and valid.
    /// </summary>
    /// <param name="context">The validation context containing the client information.</param>
    /// <param name="idTokenHint">The ID token hint string to be validated.</param>
    /// <returns>
    /// An <see cref="Result{JsonWebToken, AuthError}"/> representing the validation result,
    /// which can either be a successful token or an error.
    /// </returns>
    private async Task<Result<JsonWebToken, OidcError>> ValidateIdTokenHint(
        BackChannelAuthenticationValidationContext context,
        string idTokenHint)
    {
        // What makes a hint believable is the shared parser's question, and the audience is deliberately not
        // part of it: the three endpoints accepting the parameter disagree about who must be in it. Here it
        // is the requesting client, because OpenID Connect Core 1.0 Section 2 says an ID token's aud "MUST
        // contain the OAuth 2.0 client_id of the Relying Party".
        var result = await hintParser.ParseAsync(idTokenHint);
        if (result.TryGetFailure(out var reason))
            return new OidcError(ErrorCodes.InvalidRequest, reason);

        var token = result.GetSuccess();

        var audiences = token.Payload.Audiences;
        if (!audiences.Contains(context.ClientInfo.ClientId, StringComparer.Ordinal))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The id token hint contains token issued for the client other than specified");
        }

        // The one untyped own-issued shape that clears everything above is a JARM response JWT, which
        // carries exp and this client's audience and no sub - the same refusal the authorization endpoint
        // makes. Here it matters more: the hint is this request's identity source, so a hint naming nobody
        // would start an authentication bound to nothing, and whoever the host reached would be accepted.
        // CIBA Core 1.0 Section 13 defines the code for exactly this: the provider "is not able to identify
        // which end-user the Client wishes to be authenticated by means of the hint provided".
        if (token.Payload.Subject is not { Length: > 0 })
        {
            return new OidcError(ErrorCodes.UnknownUserId, "The id token hint names no subject");
        }

        return token;
    }
}
