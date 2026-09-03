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
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Default <see cref="IClientRequestValidator"/> for the RFC 7592 client configuration endpoint.
/// First verifies the registration access token is bound to the requested <c>client_id</c>, then
/// loads the corresponding <see cref="Features.ClientInformation.ClientInfo"/> from storage and
/// rejects the request when no record exists.
/// </summary>
/// <param name="clientInfoProvider">Store consulted for the addressed client.</param>
/// <param name="registrationAccessTokenValidator">Validator for the bearer registration access token.</param>
/// <param name="registrationAccessTokenStore">Store holding the jti of each client's current token.</param>
public class ClientRequestValidator(
    IClientInfoProvider clientInfoProvider,
    IRegistrationAccessTokenValidator registrationAccessTokenValidator,
    IRegistrationAccessTokenStore registrationAccessTokenStore) : IClientRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidClientRequest, OidcError>> ValidateAsync(ClientRequest request)
    {
        var clientId = request.ClientId.NotNull(nameof(request.ClientId));

        // The expected jti is the value recorded when this client's current registration access
        // token was issued; it binds the token so a rotated token invalidates its predecessors.
        var expectedTokenId = await registrationAccessTokenStore.GetTokenIdAsync(clientId);

        var headerErrorDescription = await registrationAccessTokenValidator.ValidateAsync(
            request.AuthorizationHeader,
            clientId,
            expectedTokenId);

        if (headerErrorDescription != null)
            return new OidcError(ErrorCodes.InvalidToken, headerErrorDescription);

        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
        if (clientInfo == null)
        {
            // RFC 7592 section 2.3: when the addressed client does not exist, the server responds
            // 401 Unauthorized and the registration access token MUST be immediately revoked.
            // The error is invalid_token, not invalid_client: this endpoint authenticates with a
            // Bearer token (RFC 6750), and invalid_client would be formatted as a Basic challenge -
            // an authentication scheme the configuration endpoint never accepts.
            await registrationAccessTokenStore.RemoveAsync(clientId);
            return new OidcError(ErrorCodes.InvalidToken, "Client does not exist on this server");
        }

        return new ValidClientRequest(request, clientInfo);
    }
}
