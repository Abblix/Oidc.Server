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
/// Loads the addressed <see cref="Features.ClientInformation.ClientInfo"/> and accepts the registration
/// access token only when it carries the jti the client's record holds.
/// </summary>
/// <param name="clientInfoProvider">Store consulted for the addressed client.</param>
/// <param name="registrationAccessTokenValidator">Validator for the bearer registration access token.</param>
/// <param name="issuerSettings">The settings of the issuer the client is registered with, which the license counts it under.</param>
public class ClientRequestValidator(
    IClientInfoProvider clientInfoProvider,
    IRegistrationAccessTokenValidator registrationAccessTokenValidator,
    IIssuerSettings issuerSettings) : IClientRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidClientRequest, OidcError>> ValidateAsync(ClientRequest request)
    {
        var clientId = request.ClientId.NotNull(nameof(request.ClientId));

        // RFC 7592 section 5: the token manages the registration whose record carries its jti, so a rotated token
        // invalidates its predecessors. A client that no longer exists, and one the settings configure, which no
        // registration made, carry none: every token for them is refused, which is also the revocation RFC 7592
        // section 2.3 asks for once the client is gone. The error is invalid_token, not invalid_client: this
        // endpoint authenticates with a Bearer token (RFC 6750), and invalid_client would be formatted as a Basic
        // challenge.
        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId);
        if (clientInfo is not { RegistrationAccessTokenId: { } expectedTokenId })
            return new OidcError(ErrorCodes.InvalidToken, "The access token unauthorized");

        var headerErrorDescription = await registrationAccessTokenValidator.ValidateAsync(
            request.AuthorizationHeader,
            clientId,
            expectedTokenId);

        if (headerErrorDescription != null)
            return new OidcError(ErrorCodes.InvalidToken, headerErrorDescription);

        clientInfo.CheckClientLicense(issuerSettings);
        return new ValidClientRequest(request, clientInfo, expectedTokenId);
    }
}
