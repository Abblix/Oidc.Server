// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
    /// <returns>A task that represents the asynchronous operation. The task result contains the validation result.</returns>
    public async Task<ClientRequestValidationResult> ValidateAsync(ClientRequest request)
    {
        var headerErrorDescription = await _registrationAccessTokenValidator.ValidateAsync(
            request.AuthorizationHeader,
            request.ClientId.NotNull(nameof(request.ClientId)));

        if (headerErrorDescription != null)
            return new ClientRequestValidationError(ErrorCodes.InvalidGrant, headerErrorDescription);

        var clientInfo = await _clientInfoProvider.TryFindClientAsync(request.ClientId).WithLicenseCheck();
        if (clientInfo == null)
            return new ClientRequestValidationError(ErrorCodes.InvalidClient, "Client does not exist on this server");

        return new ValidClientRequest(request, clientInfo);
    }
}
