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
public class ClientRequestValidator(
    IClientInfoProvider clientInfoProvider,
    IRegistrationAccessTokenValidator registrationAccessTokenValidator) : IClientRequestValidator
{
    /// <inheritdoc />
    public async Task<Result<ValidClientRequest, OidcError>> ValidateAsync(ClientRequest request)
    {
        var headerErrorDescription = await registrationAccessTokenValidator.ValidateAsync(
            request.AuthorizationHeader,
            request.ClientId.NotNull(nameof(request.ClientId)));

        if (headerErrorDescription != null)
            return new OidcError(ErrorCodes.InvalidToken, headerErrorDescription);

        var clientInfo = await clientInfoProvider.TryFindClientAsync(request.ClientId).WithLicenseCheck();
        if (clientInfo == null)
            return new OidcError(ErrorCodes.InvalidClient, "Client does not exist on this server");

        return new ValidClientRequest(request, clientInfo);
    }
}
