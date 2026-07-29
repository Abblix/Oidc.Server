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

using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Validates the <c>id_token_hint</c> parameter (OpenID Connect RP-Initiated Logout 1.0 §2):
/// verifies signature/issuer/audience but deliberately accepts expired tokens (since the
/// hint's role is to identify a no-longer-active session), then either populates
/// <c>ClientId</c> from the token's audience when the request omitted it, or asserts that
/// an explicitly supplied <c>client_id</c> matches that audience.
/// </summary>
public class IdTokenHintValidator(
    IAuthServiceJwtValidator jwtValidator,
    IClientInfoProvider clientInfoProvider) : IEndSessionContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
    {
        var request = context.Request;

        if (request.IdTokenHint.HasValue())
        {
            // The audience is checked below rather than by the shared validator, which accepts only the
            // issuer. An ID token is the one class that names a client there: OpenID Connect Core 1.0
            // Section 2 says the aud claim "MUST contain the OAuth 2.0 client_id of the Relying Party".
            var result = await jwtValidator.ValidateAsync(
                request.IdTokenHint,
                ValidationOptions.Default & ~ValidationOptions.ValidateLifetime & ~ValidationOptions.ValidateAudience);

            if (result.TryGetFailure(out var error))
                return new OidcError(ErrorCodes.InvalidRequest, $"The id token hint contains invalid token: {error.ToString()}");

            var idToken = result.GetSuccess();

            // RFC 8725 §3.12: pin the token class. The id_token_hint MUST be an ID Token; without this
            // check another own-issued token whose audience matches (an access or refresh token) would
            // be accepted here, since the audience/signature checks alone do not distinguish the class.
            if (idToken.Header.Type != JwtTypes.IdToken)
                return new OidcError(
                    ErrorCodes.InvalidRequest, "The id token hint is not an ID Token");

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

                // The client named in the audience has to exist, or the hint identifies a session belonging to
                // nobody. The shared validator used to establish this while resolving the audience; it now
                // accepts only the issuer, so the ID token's own rule is enforced here.
                var audienceClient = await clientInfoProvider
                    .TryFindClientAsync(context.ClientId)
                    .WithLicenseCheck();

                if (audienceClient == null)
                {
                    return new OidcError(
                        ErrorCodes.InvalidRequest,
                        "The id token hint names a client that is not registered");
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
