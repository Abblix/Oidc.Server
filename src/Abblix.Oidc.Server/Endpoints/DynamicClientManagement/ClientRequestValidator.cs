// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default <see cref="IClientRequestValidator"/> for the RFC 7592 client configuration endpoint.
/// Validates the registration access token, then accepts it only for the registration that holds its jti.
/// </summary>
/// <param name="registrationBinding">Finds the registration a registration access token manages.</param>
/// <param name="registrationAccessTokenValidator">Validator for the bearer registration access token.</param>
public class ClientRequestValidator(
    RegistrationAccessTokenBinding registrationBinding,
    IRegistrationAccessTokenValidator registrationAccessTokenValidator) : IClientRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidClientRequest, OidcError>> ValidateAsync(TenantDefinition tenant, ClientRequest request)
    {
        var clientId = request.ClientId.NotNull(nameof(request.ClientId));

        // RFC 7592 section 2.1 answers a token "not valid" as RFC 6750 does, whose section 3.1 names a request that
        // "uses more than one method for including an access token" an invalid_request
        if (request.HasMoreThanOneAuthorizationHeader)
            return Common.Validation.ErrorFactory.MoreThanOneBearerAuthorizationHeader;

        // The token is judged before anything is looked up, so a caller without one learns nothing about which
        // ids are registered: every id it names gets the same answer
        var tokenValidation = await registrationAccessTokenValidator.ValidateAsync(
            tenant,
            request.AuthorizationHeader,
            clientId);

        if (tokenValidation.TryGetFailure(out var error))
            return error;

        // The registration the token manages, read again here for the request: one replaced or deleted since the token
        // was judged manages it no more. The error is invalid_token, not invalid_client: this endpoint authenticates
        // with a Bearer token (RFC 6750), and invalid_client would be formatted as a Basic challenge.
        if (await registrationBinding.FindRegistrationAsync(tenant, clientId, tokenValidation.GetSuccess()) is not { } client)
            return new OidcError(ErrorCodes.InvalidToken, "The access token unauthorized");

        return new ValidClientRequest(request, client);
    }
}
