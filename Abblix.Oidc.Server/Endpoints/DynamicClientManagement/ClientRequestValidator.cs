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
/// This class is responsible for validating client requests by checking the authorization header and client existence.
/// It implements the IClientRequestValidator interface. It uses an IClientInfoProvider to retrieve client information
/// and an IRegistrationAccessTokenValidator to validate the authorization header.
/// </summary>
public class ClientRequestValidator : IClientRequestValidator
{
    public ClientRequestValidator(
        IClientInfoProvider clientInfoProvider,
        IRegistrationAccessTokenValidator registrationAccessTokenValidator)
    {
        _clientInfoProvider = clientInfoProvider;
        _registrationAccessTokenValidator = registrationAccessTokenValidator;
    }

    private readonly IClientInfoProvider _clientInfoProvider;
    private readonly IRegistrationAccessTokenValidator _registrationAccessTokenValidator;

    /// <summary>
    /// Validates a client request asynchronously by checking the authorization header and client existence.
    /// </summary>
    /// <param name="request">The client request to validate.</param>
    /// <returns>A task that returns the validation result.</returns>
    public async Task<Result<ValidClientRequest, RequestError>> ValidateAsync(ClientRequest request)
    {
        var headerErrorDescription = await _registrationAccessTokenValidator.ValidateAsync(
            request.AuthorizationHeader,
            request.ClientId.NotNull(nameof(request.ClientId)));

        if (headerErrorDescription != null)
            return new RequestError(ErrorCodes.InvalidGrant, headerErrorDescription);

        var clientInfo = await _clientInfoProvider.TryFindClientAsync(request.ClientId).WithLicenseCheck();
        if (clientInfo == null)
            return new RequestError(ErrorCodes.InvalidClient, "Client does not exist on this server");

        return new ValidClientRequest(request, clientInfo);
    }
}
