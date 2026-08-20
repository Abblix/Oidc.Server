// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
            // issuer. An ID token is the one type that names a client there: OpenID Connect Core 1.0
            // Section 2 says the aud claim "MUST contain the OAuth 2.0 client_id of the Relying Party".
            var result = await jwtValidator.ValidateAsync(
                request.IdTokenHint,
                ValidationOptions.Default & ~ValidationOptions.ValidateLifetime & ~ValidationOptions.ValidateAudience);

            if (result.TryGetFailure(out var error))
                return new OidcError(ErrorCodes.InvalidRequest, $"The id token hint contains invalid token: {error.ToString()}");

            var idToken = result.GetSuccess();

            // RFC 8725 §3.12: keep the validation rules for different kinds of JWT mutually exclusive, so
            // another own-issued token whose audience happens to match - an access or refresh token - cannot
            // be replayed here, which the signature and audience checks alone would not catch.
            //
            // Stated as a refusal rather than a requirement, because the accepting side cannot be enumerated:
            // an ID token carries no type of its own, and RFC 8725 §3.11 warns that explicit typing "may not
            // achieve disambiguation from existing kinds of JWTs, as the validation rules for existing kinds
            // of JWTs often do not use the typ Header Parameter value". What can be enumerated exactly is every
            // other type this class names, and here none of them belongs, so all of them are refused.
            if (!JwtTypes.IsPermitted(idToken.Header.Type))
                return new OidcError(
                    ErrorCodes.InvalidRequest, "The id token hint is not an ID Token");

            // A refusal by type cannot reach the one other own-issued JWT that carries no type either:
            // a signed UserInfo response, which this service signs with the same key and addresses to the
            // same client, so signature and audience both pass. What parts the two is a claim rather than
            // a header, which RFC 8725 §3.12 lists as an equal way to keep the rules mutually exclusive:
            // OpenID Connect Core 1.0 §2 makes exp REQUIRED in an ID Token, while §5.3.2 requires a signed
            // UserInfo response to carry iss and aud and nothing more.
            //
            // Presence alone is the test. A hint is accepted after expiry on purpose - it names a session
            // that has ended - so the lifetime check stays switched off above.
            if (idToken.Payload.ExpiresAt is null)
                return new OidcError(
                    ErrorCodes.InvalidRequest, "The id token hint is not an ID Token: it has no expiration time");

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
