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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default <see cref="IClientRequestValidator"/> for the RFC 7592 client configuration endpoint.
/// Validates the registration access token, then accepts it only for the registration that holds its jti.
/// </summary>
/// <param name="clientInfoManager">Store of the registrations and the token each is managed by.</param>
/// <param name="registrationAccessTokenValidator">Validator for the bearer registration access token.</param>
public class ClientRequestValidator(
    IClientInfoManager clientInfoManager,
    IRegistrationAccessTokenValidator registrationAccessTokenValidator) : IClientRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidClientRequest, OidcError>> ValidateAsync(ClientRequest request)
    {
        var clientId = request.ClientId.NotNull(nameof(request.ClientId));

        // The token is judged before anything is looked up, so a caller without one learns nothing about which
        // ids are registered: every id it names gets the same answer
        var tokenValidation = await registrationAccessTokenValidator.ValidateAsync(
            request.AuthorizationHeader,
            clientId);

        if (tokenValidation.TryGetFailure(out var error))
            return error;

        // RFC 7592 section 5: the token manages the registration holding its jti, so a rotated token invalidates
        // its predecessors. A client that no longer exists, and one the store serves from the settings, which no
        // registration made, hold none: every token for them is refused, which is also the revocation RFC 7592
        // section 2.3 asks for once the client is gone. The error is invalid_token, not invalid_client: this endpoint authenticates
        // with a Bearer token (RFC 6750), and invalid_client would be formatted as a Basic challenge.
        var client = await clientInfoManager.TryFindRegisteredClientAsync(clientId);
        if (client == null || client.RegistrationAccessTokenId != tokenValidation.GetSuccess())
            return new OidcError(ErrorCodes.InvalidToken, "The access token unauthorized");

        return new ValidClientRequest(request, client);
    }
}
